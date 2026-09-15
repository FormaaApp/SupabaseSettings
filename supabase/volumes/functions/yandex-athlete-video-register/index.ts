// Supabase Edge Function: регистрирует новое видео ученика (на проверку
// тренеру) в Yandex Cloud Video — та же роль, что yandex-video-register
// играет для видео техники, но для workout_videos, см.
// 138_yandex_video_workout_videos_column.sql. Отдельная функция, а не
// параметр kind у yandex-video-register — у workout_videos другой набор
// полей (athlete_id вместо position) и своя логика владения.
//
// Сама заливка байт (TUS PATCH) — не здесь, эта функция только
// регистрирует видео и создаёт строку в БД, приложение после нашего
// ответа заливает файл НАПРЯМУЮ в Яндекс по адресу upload_url.
//
// Владелец (athlete_id) берётся ИЗ JWT вызывающего (user.id), а не из
// тела запроса — даже если клиент пришлёт чужой athlete_id, строка всё
// равно создастся на настоящего вызывающего. Это не просто подстраховка:
// RLS-политика "Athlete manages own videos" (058_fix_video_exercise_cross_tenant_insert.sql)
// и так отклонила бы INSERT с чужим athlete_id (with check athlete_id =
// auth.uid()), но незачем давать этой проверке вообще шанс сработать —
// проще не читать чужое значение из входных данных.
//
// Доступ к exercise_id — тот же приём, что и в yandex-video-register:
// обычный SELECT через userClient (RLS workout_exercises), не отдельная
// проверка руками.
//
// Настройка — деплой копированием файла (см. self-host/deploy_functions.sh),
// без отдельного переключателя JWT: у self-hosted edge-runtime это одна
// общая настройка на весь контейнер functions (FUNCTIONS_VERIFY_JWT в
// .env), не per-function — см. подробное объяснение в yandex-video-register/index.ts.
// Проверка JWT — в коде этой функции ниже (authHeader + userClient.auth.getUser()).
// Secrets — те же четыре YANDEX_*, что и у остальных функций пилота
// (уже настроены, если yandex-video-register уже деплоился).

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
  exercise_id: string
  file_name: string
  file_size: number
  // Превью грузится клиентом напрямую на Supabase Storage ДО вызова этой
  // функции (см. YandexVideoService.uploadAthleteVideo).
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

    const { exercise_id, file_name, file_size, thumbnail_path } = (await req.json()) as RegisterPayload
    if (!exercise_id || !file_name || !file_size) {
      return new Response(JSON.stringify({ error: "Missing exercise_id/file_name/file_size" }), { status: 400 })
    }

    const { data: exerciseRows, error: exerciseError } = await userClient
      .from("workout_exercises")
      .select("id")
      .eq("id", exercise_id)
      .limit(1)
    if (exerciseError || !exerciseRows || exerciseRows.length === 0) {
      return new Response(JSON.stringify({ error: "Not authorized for this exercise" }), { status: 403 })
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

    // athlete_id = user.id (из JWT), НЕ из тела запроса — см. комментарий
    // в начале файла.
    const { data: insertedRow, error: insertError } = await userClient
      .from("workout_videos")
      .insert({ athlete_id: user.id, exercise_id, yandex_video_id: videoId, thumbnail_path: thumbnail_path ?? null })
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
