// Supabase Edge Function: регистрирует новое видео в Yandex Cloud Video и
// отдаёт приложению ссылку для загрузки по протоколу TUS.
//
// ПИЛОТ перехода с Supabase Storage на Yandex Cloud Video — только видео
// техники (workout_exercise_technique_videos), см. 137_yandex_video_pilot_column.sql.
// Сама заливка байт (TUS PATCH) — не здесь, эта функция только
// регистрирует видео и создаёт строку в БД, приложение после нашего
// ответа заливает файл НАПРЯМУЮ в Яндекс по adресу upload_url.
//
// Права доступа проверяются НЕ отдельной SQL-логикой здесь, а тем же
// самым userClient (JWT вызывающего) — тот же самый RLS у
// workout_exercises/workout_exercise_technique_videos, что уже проверен
// аудитом безопасности, просто переиспользуется через обычный
// .select()/.insert() вместо service_role. Если RLS это упражнение не
// пропустит (не твой ученик/не твоя самотренировка) — запрос вернёт 0
// строк, и мы откажем, ничего не дублируя руками.
//
// Настройка (Supabase Dashboard -> Edge Functions -> "yandex-video-register"):
// 1. Deploy этот файл как есть.
// 2. "Enforce JWT Verification" — ВКЛЮЧЕНА (в отличие от send-push): эту
//    функцию вызывает сам пользователь из приложения со своим JWT, не
//    внутренний триггер.
// 3. Secrets:
//    - YANDEX_SERVICE_ACCOUNT_ID, YANDEX_KEY_ID, YANDEX_PRIVATE_KEY —
//      три поля из JSON-ключа сервисного аккаунта (`service_account_id`,
//      `id`, `private_key`), см. README self-host / инструкцию перехода.
//    - YANDEX_CHANNEL_ID — id канала, video.yandex.cloud -> ваш канал.
//    SUPABASE_URL / SUPABASE_ANON_KEY подставляются автоматически.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

function base64url(data: Uint8Array): string {
  let str = ""
  for (const byte of data) str += String.fromCharCode(byte)
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

// Ключ сервисного аккаунта Yandex — PKCS8 PEM, тот же формат, что и APNs
// ключ в send-push, только алгоритм другой (RSA-PSS, не ECDSA — так
// требует Yandex IAM, см. https://yandex.cloud/en/docs/iam/operations/iam-token/create-for-sa).
//
// Реальный private_key из выгруженного JSON-ключа начинается со строки
// "PLEASE DO NOT REMOVE THIS LINE! Yandex.Cloud SA Key ID <...>" ДО
// самого "-----BEGIN PRIVATE KEY-----" — если просто вырезать маркеры
// BEGIN/END, как раньше, эта строка осталась бы приклеенной к началу
// base64-тела и ломала бы decode. Проверено на реальном ключе (живой
// обмен на IAM-токен) — вытаскиваем строго то, что МЕЖДУ маркерами.
async function importYandexPrivateKey(pem: string): Promise<CryptoKey> {
  const match = pem.match(/-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/)
  if (!match) {
    throw new Error("YANDEX_PRIVATE_KEY: PEM markers not found")
  }
  const raw = Uint8Array.from(atob(match[1].replace(/\s+/g, "")), (c) => c.charCodeAt(0))
  return crypto.subtle.importKey("pkcs8", raw, { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"])
}

/// IAM-токен Yandex живёт максимум час здесь (лимит — 12ч, но сами
/// рекомендуют обновлять чаще) — кешируем между вызовами тёплого
/// инстанса, тот же приём, что и у APNs JWT в send-push.
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
  // Поле называется то ли iamToken, то ли iam_token в разных версиях
  // API/примерах — принимаем оба, чтобы не упасть на одном написании.
  const token: string | undefined = data.iamToken ?? data.iam_token
  if (!response.ok || !token) {
    throw new Error(`Yandex IAM token exchange failed: ${JSON.stringify(data)}`)
  }
  cachedIamToken = { token, expiresAt: now + 3600 }
  return token
}

interface RegisterPayload {
  exercise_id: string
  file_name: string
  file_size: number
  position: number
  // Превью грузится клиентом напрямую на Supabase Storage ДО вызова этой
  // функции (см. YandexVideoService.uploadTechniqueVideo) — пилот переносит
  // на Yandex только сам видеофайл, не JPEG-кадр.
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

    const { exercise_id, file_name, file_size, position, thumbnail_path } = (await req.json()) as RegisterPayload
    if (!exercise_id || !file_name || !file_size) {
      return new Response(JSON.stringify({ error: "Missing exercise_id/file_name/file_size" }), { status: 400 })
    }

    // Граница доступа — обычный SELECT через userClient (RLS
    // workout_exercises), не отдельная проверка руками: 0 строк = отказ.
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
        // Временная ссылка (до 12ч на просмотр), не публичная навсегда —
        // саму ссылку на конкретный показ выдаёт yandex-video-playback-url
        // по требованию, та же роль, что раньше играл signed URL
        // Supabase Storage.
        signUrlAccess: {},
      }),
    })
    // Проверено на реальном аккаунте 2026-09-12: ответ — не плоский объект
    // видео, а обёртка "операции" ({done, metadata, response: {...видео...}}) —
    // само видео лежит в response.*, не в корне.
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

    // Та же INSERT-политика workout_exercise_technique_videos, что уже
    // была для Supabase Storage путей (userClient — не service_role) —
    // storage_path оставляем пустым, yandex_video_id — новый (137).
    // .select().single() — клиенту (YandexVideoService.uploadTechniqueVideo)
    // нужна вся строка целиком (как раньше возвращал старый путь через
    // Supabase Storage), а не только сам yandex_video_id, иначе пришлось бы
    // делать отдельный round-trip за только что созданной строкой.
    const { data: insertedRow, error: insertError } = await userClient
      .from("workout_exercise_technique_videos")
      .insert({ exercise_id, yandex_video_id: videoId, position, thumbnail_path: thumbnail_path ?? null })
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

