// Supabase Edge Function: выдаёт временную ссылку на просмотр конкретного
// видео из Yandex Cloud Video — та же роль, что раньше играл
// WorkoutService.signedTechniqueVideoURL (createSignedURL Supabase
// Storage), просто на новом бэкенде. ПИЛОТ — только видео техники, см.
// 137_yandex_video_pilot_column.sql и yandex-video-register.
//
// Права — тем же принципом, что и у регистрации: проверяем через
// userClient (JWT вызывающего), не через service_role — если RLS
// workout_exercise_technique_videos эту строку не отдаёт (ученик смотрит
// не свою тренировку и т.п.), запрос вернёт 0 строк, отказываем.
//
// Настройка: как у yandex-video-register — "Enforce JWT Verification"
// включена, те же секреты YANDEX_SERVICE_ACCOUNT_ID/YANDEX_KEY_ID/
// YANDEX_PRIVATE_KEY (IAM-обмен продублирован здесь — та же логика, что
// в yandex-video-register, но это отдельно деплоящаяся функция, общий
// код между self-host Edge Functions не шарится без своей сборки, тот же
// подход, что и у остальных функций в этом проекте).

import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

function base64url(data: Uint8Array): string {
  let str = ""
  for (const byte of data) str += String.fromCharCode(byte)
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

// Реальный private_key из JSON-ключа Yandex начинается со строки "PLEASE
// DO NOT REMOVE THIS LINE! ..." ДО "-----BEGIN PRIVATE KEY-----" — вырезаем
// строго то, что между маркерами, а не просто убираем сами маркеры (иначе
// эта строка остаётся приклеенной к base64-телу и ломает decode).
// Проверено на реальном ключе — живой обмен на IAM-токен успешен.
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

interface PlaybackPayload {
  video_row_id: string
  // "athlete" — workout_videos (видео ученика на проверку, см.
  // 138_yandex_video_workout_videos_column.sql); по умолчанию "technique"
  // (workout_exercise_technique_videos) — для обратной совместимости со
  // старыми вызовами приложения, которые это поле ещё не отправляют.
  kind?: "technique" | "athlete"
}

const TABLE_BY_KIND: Record<string, string> = {
  technique: "workout_exercise_technique_videos",
  athlete: "workout_videos",
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

    const { video_row_id, kind } = (await req.json()) as PlaybackPayload
    if (!video_row_id) {
      return new Response(JSON.stringify({ error: "Missing video_row_id" }), { status: 400 })
    }
    const table = TABLE_BY_KIND[kind ?? "technique"]

    // RLS нужной таблицы решает, видно ли вообще эту строку вызывающему —
    // 0 строк здесь означает "нет прав", не "видео не существует" (не
    // различаем специально, чтобы не палить существование).
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

    // Операция называется generateDownloadURL (заглавный URL в конце) —
    // подтверждено. Ответ — "операция" ({done, response: {downloadUrl}}).
    // ПОДТВЕРЖДЕНО ВЖИВУЮ (2026-09-13, реальное видео): downloadUrl отдаёт
    // валидный MP4 (curl + `file` подтвердили ISO Media контейнер), но
    // сервер возвращает "Content-Type: application/octet-stream" и путь
    // без расширения — из-за этого AVPlayer/AVURLAsset на клиенте не мог
    // сам определить тип контейнера и считал isPlayable=false, хотя байты
    // были полностью нормальным видео. Исправлено на клиенте
    // (AVURLAssetOverrideMIMETypeKey, см. FullScreenTechniqueVideoView) —
    // здесь менять нечего, отдельный SDK-плеер (YandexCloudVideoPlayerView)
    // в итоге не понадобился, обычный AVPlayer справляется с downloadUrl
    // как есть.
    const downloadResponse = await fetch(
      `https://video.api.cloud.yandex.net/video/v1/videos/${yandexVideoId}:generateDownloadURL`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${iamToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
      }
    )
    const downloadData = await downloadResponse.json()
    const playbackUrl: string | undefined =
      downloadData.response?.downloadUrl ?? downloadData.downloadUrl ?? downloadData.url
    if (!downloadResponse.ok || !playbackUrl) {
      return new Response(
        JSON.stringify({ error: `Yandex download URL generation failed: ${JSON.stringify(downloadData)}` }),
        { status: 502 }
      )
    }

    return new Response(JSON.stringify({ playback_url: playbackUrl }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), { status: 500 })
  }
})

