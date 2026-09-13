// Supabase Edge Function: отправка настоящего push через APNs.
//
// Кто её вызывает: Postgres-триггер on_notification_send_push
// (см. Supabase/092_push_notifications.sql) при каждой новой строке в
// notifications — то есть при любом уже существующем в приложении событии
// (комментарий тренера, "жду" от тренера, сообщение в чате, ежедневные
// напоминания и т.д.), без отдельной интеграции под каждое из них.
//
// Как задеплоить (без установки чего-либо на компьютер):
// 1. Сначала нужен APNs-ключ из Apple Developer аккаунта (того самого, где
//    сейчас зарегистрировано приложение): Certificates, Identifiers & Profiles
//    -> Keys -> "+" -> отметить "Apple Push Notifications service (APNs)" ->
//    Continue -> Register -> Download (.p8-файл скачивается только один
//    раз — если потеряете, придётся делать новый ключ) -> запомните Key ID,
//    показанный на этой же странице.
// 2. Supabase Dashboard -> Edge Functions -> Create a new function,
//    назовите её ровно "send-push", вставьте этот код, Deploy.
// 3. В настройках функции найдите переключатель "Enforce JWT Verification"
//    (или "Verify JWT") и ВЫКЛЮЧИТЕ его — эту функцию дёргает только наш
//    собственный Postgres-триггер изнутри Supabase, не пользователь из
//    приложения, поэтому проверка чужого JWT тут не нужна и не пройдёт.
// 4. Там же в Secrets/Environment variables добавьте:
//    - APNS_KEY_ID = Key ID из шага 1
//    - APNS_TEAM_ID = 3DZAF454Q2 (Team ID из Apple Developer)
//    - APNS_AUTH_KEY = содержимое скачанного .p8-файла целиком, включая
//      строки -----BEGIN PRIVATE KEY----- / -----END PRIVATE KEY-----
//    - APNS_BUNDLE_ID = com.SwiftWork.KBJUCouchApp
//    - APNS_ENVIRONMENT = sandbox — ВАЖНО: это значение для локальных сборок
//      из Xcode. Как только появятся сборки через TestFlight/App Store,
//      смените на production — они используют другой сервер APNs, и с
//      неверным значением push просто не будет доходить без явной ошибки.
//    SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY подставляются автоматически.
// 5. Готово — новый Deploy не нужен, секреты подхватываются на лету.
//    Если какой-то из APNS_*-секретов ещё не задан, функция просто ничего
//    не отправляет (безопасный no-op), остальная часть приложения работает
//    как обычно.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

interface NotificationPayload {
  recipient_id: string
  title: string
  body: string | null
}

// APNs ждёт JWT максимум на час; пересоздаём заметно раньше, чтобы не словить
// "истёк прямо во время запроса", и кешируем между вызовами тёплого инстанса.
let cachedToken: { jwt: string; expiresAt: number } | null = null

function base64url(data: Uint8Array): string {
  let str = ""
  for (const byte of data) str += String.fromCharCode(byte)
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

async function importApnsKey(pem: string): Promise<CryptoKey> {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "")
  const raw = Uint8Array.from(atob(body), (c) => c.charCodeAt(0))
  return crypto.subtle.importKey(
    "pkcs8",
    raw,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  )
}

async function getApnsJWT(keyId: string, teamId: string, authKeyPem: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  if (cachedToken && cachedToken.expiresAt > now + 60) {
    return cachedToken.jwt
  }

  const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", kid: keyId })))
  const claims = base64url(new TextEncoder().encode(JSON.stringify({ iss: teamId, iat: now })))
  const signingInput = `${header}.${claims}`

  const key = await importApnsKey(authKeyPem)
  // WebCrypto ECDSA возвращает подпись сразу в формате r||s (IEEE P1363),
  // ровно как ожидает JWS ES256 — конвертация из ASN.1/DER не нужна.
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(signingInput)
  )

  const jwt = `${signingInput}.${base64url(new Uint8Array(signature))}`
  cachedToken = { jwt, expiresAt: now + 55 * 60 }
  return jwt
}

Deno.serve(async (req) => {
  try {
    const { recipient_id, title, body } = (await req.json()) as NotificationPayload

    const keyId = Deno.env.get("APNS_KEY_ID")
    const teamId = Deno.env.get("APNS_TEAM_ID")
    const authKeyPem = Deno.env.get("APNS_AUTH_KEY")
    const bundleId = Deno.env.get("APNS_BUNDLE_ID")
    const environment = Deno.env.get("APNS_ENVIRONMENT") ?? "sandbox"

    // Секреты ещё не заданы (обычная ситуация до ручной настройки APNs) —
    // тихо ничего не делаем, это не ошибка обработки самого уведомления.
    if (!keyId || !teamId || !authKeyPem || !bundleId) {
      return new Response("APNs not configured yet, skipping", { status: 200 })
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    const adminClient = createClient(supabaseUrl, serviceRoleKey)

    const { data: profile } = await adminClient
      .from("profiles")
      .select("push_device_token")
      .eq("id", recipient_id)
      .single()

    const deviceToken = profile?.push_device_token
    if (!deviceToken) {
      return new Response("No device token for recipient, skipping", { status: 200 })
    }

    const jwt = await getApnsJWT(keyId, teamId, authKeyPem)
    const host = environment === "production" ? "api.push.apple.com" : "api.sandbox.push.apple.com"

    const apnsResponse = await fetch(`https://${host}/3/device/${deviceToken}`, {
      method: "POST",
      headers: {
        "authorization": `bearer ${jwt}`,
        "apns-topic": bundleId,
        "apns-push-type": "alert",
        "apns-priority": "10",
      },
      body: JSON.stringify({
        aps: {
          alert: { title, body: body ?? "" },
          sound: "default",
        },
      }),
    })

    // 410 (Unregistered) / 400 BadDeviceToken — токен больше не рабочий
    // (переустановка приложения, выход из аккаунта и т.п.), чистим его,
    // чтобы не пытаться слать в никуда каждый раз.
    if (apnsResponse.status === 410 || apnsResponse.status === 400) {
      await adminClient.from("profiles").update({ push_device_token: null }).eq("id", recipient_id)
    }

    return new Response(`APNs responded ${apnsResponse.status}`, { status: 200 })
  } catch (e) {
    return new Response(String(e), { status: 500 })
  }
})
