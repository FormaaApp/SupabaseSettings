// Supabase Edge Function: удаляет видео из Yandex Cloud Video при удалении
// самой строки (или явном удалении видео пользователем) — без этого вызова
// строка в workout_exercise_technique_videos пропадает, а сам видеофайл
// остаётся висеть на канале Yandex НАВСЕГДА и продолжает тарифицироваться
// (хранение — 0,0033 ₽/ГБ в час, копейки за штуку, но без чистки растёт
// бесконечно на каждое удалённое упражнение/видео). ПИЛОТ — только видео
// техники, см. 137_yandex_video_pilot_column.sql.
//
// Права — тем же принципом, что и у остальных функций пилота: проверяем
// через userClient (JWT вызывающего), не через service_role — если RLS
// workout_exercise_technique_videos эту строку не отдаёт, отказываем. Саму
// строку в БД эта функция НЕ удаляет — это по-прежнему делает клиент
// (WorkoutService.deleteTechniqueVideo), функция только чистит внешний
// ресурс на Yandex.
//
// Настройка: как у yandex-video-register — "Enforce JWT Verification"
// включена, те же секреты YANDEX_SERVICE_ACCOUNT_ID/YANDEX_KEY_ID/
// YANDEX_PRIVATE_KEY (IAM-обмен продублирован здесь по тому же принципу,
// что и в остальных функциях пилота — общий код между self-host Edge
// Functions не шарится без своей сборки).

import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

function base64url(data: Uint8Array): string {
  let str = ""
  for (const byte of data) str += String.fromCharCode(byte)
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

async function importYandexPrivateKey(pem: string): Promise<CryptoKey> {
  const match = pem.match(/-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/)
  if (!match) {
    throw new Error("YANDEX_PRIVATE_KEY: PEM markers not found")
  }
  const raw = Uint8Array.from(atob(match[1].replace(/\s+/g, "")), (c) => c.charCodeAt(0))
  return crypto.subtle.importKey("pkcs8", raw, { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"])
}

let cachedIamToken: { token: string; expiresAt: number } | null = null

async function getYandexIamToken(): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  if (cachedIamToken && cachedIamToken.expiresAt > now + 60) {
    return cachedIamToken.token
  }

  const serviceAccountId = Deno.env.get("YANDEX_SERVICE_ACCOUNT_ID")
  const keyId = Deno.env.get("YANDEX_KEY_ID")
  const privateKeyPem = Deno.env.get("YANDEX_PRIVATE_KEY")
  if (!serviceAccountId || !keyId || !privateKeyPem) {
    throw new Error("Yandex service account secrets not configured")
  }

  const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: "PS256", kid: keyId, typ: "JWT" })))
  const claims = base64url(new TextEncoder().encode(JSON.stringify({
    iss: serviceAccountId,
    aud: "https://iam.api.cloud.yandex.net/iam/v1/tokens",
    iat: now,
    exp: now + 3600,
  })))
  const signingInput = `${header}.${claims}`
  const key = await importYandexPrivateKey(privateKeyPem)
  const signature = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, key, new TextEncoder().encode(signingInput))
  const jwt = `${signingInput}.${base64url(new Uint8Array(signature))}`

  const response = await fetch("https://iam.api.cloud.yandex.net/iam/v1/tokens", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jwt }),
  })
  const data = await response.json()
  const token: string | undefined = data.iamToken ?? data.iam_token
  if (!response.ok || !token) {
    throw new Error(`Yandex IAM token exchange failed: ${JSON.stringify(data)}`)
  }
  cachedIamToken = { token, expiresAt: now + 3600 }
  return token
}

interface DeletePayload {
  video_row_id: string
  // "athlete" — workout_videos; "library" — coach_exercise_library_videos;
  // по умолчанию "technique" (workout_exercise_technique_videos), см.
  // yandex-video-playback-url.
  kind?: "technique" | "athlete" | "library"
}

const TABLE_BY_KIND: Record<string, string> = {
  technique: "workout_exercise_technique_videos",
  athlete: "workout_videos",
  library: "coach_exercise_library_videos",
}

Deno.serve(async (req) => {
  try {
    const authHeader = req.headers.get("Authorization")
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "No authorization header" }), { status: 401 })
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!
    const userClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    })

    const { data: { user }, error: userError } = await userClient.auth.getUser()
    if (userError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 })
    }

    const { video_row_id, kind } = (await req.json()) as DeletePayload
    if (!video_row_id) {
      return new Response(JSON.stringify({ error: "Missing video_row_id" }), { status: 400 })
    }
    const table = TABLE_BY_KIND[kind ?? "technique"]

    // RLS нужной таблицы решает, видно ли вообще эту строку вызывающему —
    // тот же принцип, что и у yandex-video-playback-url.
    const { data: videoRows, error: videoError } = await userClient
      .from(table)
      .select("yandex_video_id")
      .eq("id", video_row_id)
      .limit(1)
    const yandexVideoId = videoRows?.[0]?.yandex_video_id as string | undefined
    if (videoError || !yandexVideoId) {
      return new Response(JSON.stringify({ error: "Not found or not a Yandex-backed video" }), { status: 404 })
    }

    const iamToken = await getYandexIamToken()

    // Подтверждено вживую (2026-09-12, тестовые регистрации): операция
    // называется просто DELETE /video/v1/videos/{id}, без отдельного
    // ":action" в пути — в отличие от generateDownloadURL.
    const deleteResponse = await fetch(
      `https://video.api.cloud.yandex.net/video/v1/videos/${yandexVideoId}`,
      { method: "DELETE", headers: { "Authorization": `Bearer ${iamToken}` } }
    )
    // 404 здесь — не ошибка вызывающего: видео на Yandex уже могло быть
    // удалено раньше (повторный вызов, гонка) — трактуем как успех, а не
    // как повод не дать клиенту завершить удаление строки в БД.
    if (!deleteResponse.ok && deleteResponse.status !== 404) {
      const deleteData = await deleteResponse.text()
      return new Response(
        JSON.stringify({ error: `Yandex video deletion failed: ${deleteData}` }),
        { status: 502 }
      )
    }

    return new Response(JSON.stringify({ deleted: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), { status: 500 })
  }
})
