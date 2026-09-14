// Supabase Edge Function: регистрирует новое видео МЕДИАТЕКИ (не видео
// конкретного упражнения) в Yandex Cloud Video — та же роль, что
// yandex-video-register играет для workout_exercise_technique_videos, но
// для coach_exercise_library_videos, см. 140_yandex_video_library_column.sql.
// Отдельная функция, а не параметр kind у yandex-video-register — другой
// набор полей (library_id вместо exercise_id) и своя проверка владения.
//
// Сама заливка байт (TUS PATCH) — не здесь, эта функция только
// регистрирует видео и создаёт строку в БД, приложение после нашего
// ответа заливает файл НАПРЯМУЮ в Яндекс по адресу upload_url.
//
// Владение — обычный SELECT через userClient (RLS coach_exercise_library,
// "Coach manages own exercise library" — coach_id = auth.uid()), не
// отдельная проверка руками: 0 строк = отказ, тот же приём, что и в
// yandex-video-register/yandex-athlete-video-register.
//
// Настройка (Supabase Dashboard -> Edge Functions -> "yandex-library-video-register"):
// 1. Deploy этот файл как есть.
// 2. "Enforce JWT Verification" — ВКЛЮЧЕНА, как у остальных функций пилота.
// 3. Secrets — те же четыре YANDEX_*, что и у остальных функций пилота
//    (уже настроены).

import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

function base64url(data: Uint8Array): string {
  let str = ""
  for (const byte of data) str += String.fromCharCode(byte)
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

async function importYandexPrivateKey(pem: string): Promise<CryptoKey> {
  const match = pem.match(/-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/)
  if (!match) throw new Error("YANDEX_PRIVATE_KEY: PEM markers not found")
  const raw = Uint8Array.from(atob(match[1].replace(/\s+/g, "")), (c) => c.charCodeAt(0))
  return crypto.subtle.importKey("pkcs8", raw, { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"])
}

let cachedIamToken: { token: string; expiresAt: number } | null = null

async function getYandexIamToken(): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  if (cachedIamToken && cachedIamToken.expiresAt > now + 60) return cachedIamToken.token

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
  if (!response.ok || !token) throw new Error(`Yandex IAM token exchange failed: ${JSON.stringify(data)}`)
  cachedIamToken = { token, expiresAt: now + 3600 }
  return token
}

interface RegisterPayload {
  library_id: string
  file_name: string
  file_size: number
  position: number
  // Превью грузится клиентом напрямую на Supabase Storage ДО вызова этой
  // функции (см. YandexVideoService.uploadLibraryVideo).
  thumbnail_path?: string
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

    const { library_id, file_name, file_size, position, thumbnail_path } = (await req.json()) as RegisterPayload
    if (!library_id || !file_name || !file_size) {
      return new Response(JSON.stringify({ error: "Missing library_id/file_name/file_size" }), { status: 400 })
    }

    const { data: libraryRows, error: libraryError } = await userClient
      .from("coach_exercise_library")
      .select("id")
      .eq("id", library_id)
      .limit(1)
    if (libraryError || !libraryRows || libraryRows.length === 0) {
      return new Response(JSON.stringify({ error: "Not authorized for this library entry" }), { status: 403 })
    }

    const channelId = Deno.env.get("YANDEX_CHANNEL_ID")
    if (!channelId) {
      return new Response(JSON.stringify({ error: "YANDEX_CHANNEL_ID not configured" }), { status: 500 })
    }
    const iamToken = await getYandexIamToken()

    const registerResponse = await fetch("https://video.api.cloud.yandex.net/video/v1/videos", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${iamToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        channel_id: channelId,
        title: file_name,
        tusd: { file_size, file_name },
        signUrlAccess: {},
      }),
    })
    const registerData = await registerResponse.json()
    const video = registerData.response
    const videoId: string | undefined = video?.id
    const uploadUrl: string | undefined = video?.tusd?.url
    if (!registerResponse.ok || !videoId || !uploadUrl) {
      return new Response(
        JSON.stringify({ error: `Yandex Video registration failed: ${JSON.stringify(registerData)}` }),
        { status: 502 }
      )
    }

    const { data: insertedRow, error: insertError } = await userClient
      .from("coach_exercise_library_videos")
      .insert({ library_id, yandex_video_id: videoId, position, thumbnail_path: thumbnail_path ?? null })
      .select()
      .single()
    if (insertError || !insertedRow) {
      return new Response(JSON.stringify({ error: insertError?.message ?? "Insert failed" }), { status: 400 })
    }

    return new Response(JSON.stringify({ video: insertedRow, upload_url: uploadUrl }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), { status: 500 })
  }
})
