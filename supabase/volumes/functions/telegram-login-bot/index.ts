// Supabase Edge Function: вебхук бота @formaaaAppbot — device-flow вход в
// Forma через Telegram для iOS.
//
// Поток целиком:
// 1. iOS генерирует случайный 6-значный код и показывает его прямо в
//    приложении, параллельно пытаясь открыть Telegram на чате с ботом
//    (tg://resolve?domain=formaaaAppbot&start=<код>).
// 2. Deep-link start= не всегда долетает до бота (если чат с ним уже
//    существует, Telegram иногда просто открывает чат, ничего не
//    отправляя — наблюдали это на реальном устройстве несколько раз, и
//    через tg://, и через https://t.me/...), поэтому это лишь "быстрый
//    путь": пользователь либо видит уже готовое /start <код> и жмёт
//    отправить, либо — если ничего не подставилось — сам набирает код,
//    который видит в приложении, и шлёт его боту обычным сообщением.
//    Сообщение боту доходит ВСЕГДА, в отличие от deep-link параметра.
// 3. Эта функция принимает и "/start <код>", и голый "<код>" — создаёт
//    (или находит) пользователя Supabase по telegram id (синтетический
//    email) и кладёт готовую сессию в telegram_login_requests по этому
//    коду.
// 4. iOS в это время опрашивает telegram-login-poll с тем же кодом, пока
//    не получит токены сессии (см. AuthService.signInWithTelegram()).
//
// Настройка (без установки чего-либо на компьютер):
// 1. Supabase Dashboard -> Edge Functions -> Create a new function,
//    назовите её ровно "telegram-login-bot", вставьте этот код, Deploy.
// 2. Secrets/Environment variables:
//    - MINI_APP_BOT_TOKEN = токен бота @formaaaAppbot от BotFather
//    - TELEGRAM_WEBHOOK_SECRET = произвольная случайная строка (придумайте сами)
//    - SERVICE_ROLE_KEY = вручную из Dashboard -> Project Settings -> API ->
//      "Secret keys" (или "service_role" на старых проектах) — автоподставляемый
//      SUPABASE_SERVICE_ROLE_KEY на практике не даёт реальных прав у
//      проектов с новым форматом ключей.
//    SUPABASE_URL подставляется автоматически.
// 3. Подключите webhook ИМЕННО у бота мини-приложения (замените плейсхолдеры):
//      curl -X POST "https://api.telegram.org/bot<MINI_APP_BOT_TOKEN>/setWebhook" \
//        -d "url=<URL_ФУНКЦИИ>" \
//        -d "secret_token=<TELEGRAM_WEBHOOK_SECRET>"
// 4. Прогоните 097_telegram_profile_update_fn.sql, 100_telegram_username.sql,
//    103_telegram_login_code.sql и 104_telegram_login_rpc.sql, если ещё не
//    прогоняли.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

async function tgCall(token: string, method: string, body: Record<string, unknown>) {
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })
  return res.json()
}

// И "/start 482913" (если deep-link сработал), и голый "482913"
// (пользователь набрал сам) — см. п.2 в шапке файла.
const LOGIN_CODE_RE = /^(?:\/start\s+)?(\d{6})$/

Deno.serve(async (req) => {
  try {
    const token = Deno.env.get("MINI_APP_BOT_TOKEN")
    const webhookSecret = Deno.env.get("TELEGRAM_WEBHOOK_SECRET")

    if (!token || !webhookSecret) {
      return new Response("Missing bot secrets", { status: 500 })
    }
    if (req.headers.get("X-Telegram-Bot-Api-Secret-Token") !== webhookSecret) {
      return new Response("Unauthorized", { status: 401 })
    }

    const update = await req.json()
    const message = update.message
    const text: string | undefined = message?.text?.trim()
    const match = text?.match(LOGIN_CODE_RE)

    if (!match) {
      if (message?.chat?.id) {
        await tgCall(token, "sendMessage", {
          chat_id: message.chat.id,
          text: "Отправьте сюда 6-значный код, который показан в приложении Forma на экране входа.",
        })
      }
      return new Response("ok")
    }

    const loginCode = match[1]
    const from = message.from
    if (!from?.id) {
      return new Response("ok")
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!
    const serviceRoleKey = Deno.env.get("SERVICE_ROLE_KEY") ?? Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    const admin = createClient(supabaseUrl, serviceRoleKey)

    const syntheticEmail = `tg_${from.id}@telegram.forma.local`

    let linkResult = await admin.auth.admin.generateLink({ type: "magiclink", email: syntheticEmail })

    if (linkResult.error) {
      const { error: createError } = await admin.auth.admin.createUser({
        email: syntheticEmail,
        password: crypto.randomUUID() + crypto.randomUUID(),
        email_confirm: true,
        user_metadata: {
          telegram_user_id: from.id,
          full_name: [from.first_name, from.last_name].filter(Boolean).join(" ") || from.username,
        },
      })
      if (createError) {
        await tgCall(token, "sendMessage", { chat_id: message.chat.id, text: `Не получилось войти: ${createError.message}` })
        return new Response("ok")
      }
      linkResult = await admin.auth.admin.generateLink({ type: "magiclink", email: syntheticEmail })
      if (linkResult.error) {
        await tgCall(token, "sendMessage", { chat_id: message.chat.id, text: `Не получилось войти: ${linkResult.error.message}` })
        return new Response("ok")
      }
    }

    const targetUserId = linkResult.data.user?.id
    if (!targetUserId) {
      await tgCall(token, "sendMessage", { chat_id: message.chat.id, text: "Не получилось войти: сервер не выдал сессию." })
      return new Response("ok")
    }

    // Обновляем профиль ДО verifyOtp — verifyOtp переключает сессию ЭТОГО
    // клиента supabase-js на только что вошедшего пользователя, и всё после
    // неё выполняется уже не под service_role (та самая история с
    // "permission denied for function update_telegram_profile").
    const displayName = [from.first_name, from.last_name].filter(Boolean).join(" ") || from.username
    await admin.rpc("update_telegram_profile", {
      p_user_id: targetUserId,
      p_telegram_user_id: from.id,
      p_avatar_url: null,
      p_full_name: displayName ?? null,
      p_telegram_username: from.username ?? null,
    })

    // auth.users хранит один confirmation_token на пользователя: если для
    // ЭТОГО ЖЕ telegram-аккаунта параллельно обрабатывается второй запрос на
    // вход (deep-link сам отправил /start И пользователь следом отправил код
    // ещё раз вручную, либо Telegram повторно доставил тот же вебхук), более
    // свежий generateLink затирает токен более раннего — тогда verifyOtp
    // первого падает с "Email link is invalid or has expired", хотя всё
    // сделано правильно. Поэтому при таком сбое генерируем ссылку заново и
    // пробуем ещё раз, а не сдаёмся сразу.
    let otpData: { session: { access_token: string; refresh_token: string } | null } | undefined
    let lastErrorMessage: string | undefined
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt > 0) {
        await new Promise((resolve) => setTimeout(resolve, 400))
      }
      const retryLink = attempt === 0 ? linkResult : await admin.auth.admin.generateLink({ type: "magiclink", email: syntheticEmail })
      const tokenHash = retryLink.data?.properties?.hashed_token
      if (retryLink.error || !tokenHash) {
        lastErrorMessage = retryLink.error?.message ?? "сервер не выдал сессию"
        continue
      }
      const { data, error } = await admin.auth.verifyOtp({ type: "magiclink", token_hash: tokenHash })
      if (error || !data.session) {
        lastErrorMessage = error?.message ?? "нет сессии"
        continue
      }
      otpData = data
      break
    }
    if (!otpData?.session) {
      await tgCall(token, "sendMessage", { chat_id: message.chat.id, text: `Не получилось войти: ${lastErrorMessage ?? "неизвестная ошибка"}` })
      return new Response("ok")
    }

    // security definer функция (104_telegram_login_rpc.sql) — прямой upsert
    // в таблицу упирался в "new row violates row-level security policy":
    // тот же самый ключ, который здесь считается service_role, на практике
    // им не является (та же история, что и с update_telegram_profile).
    // upsert внутри неё, а не insert — пользователь может отправить один и
    // тот же код дважды (например, сначала сработал deep-link, а потом он
    // же вручную отправил тот же код ещё раз), это не должно падать ошибкой
    // уникальности.
    //
    // Отдельный клиент, а не переиспользование admin: admin.auth.verifyOtp()
    // выше переключает сессию ЭТОГО клиента на только что вошедшего
    // пользователя (роль authenticated), а store_telegram_login_session
    // закрыта от authenticated в 105_lock_down_telegram_login_rpc.sql —
    // вызов через admin падал с "permission denied for function
    // store_telegram_login_session".
    const serviceClient = createClient(supabaseUrl, serviceRoleKey)
    const { error: insertError } = await serviceClient.rpc("store_telegram_login_session", {
      p_code: loginCode,
      p_access_token: otpData.session.access_token,
      p_refresh_token: otpData.session.refresh_token,
    })

    if (insertError) {
      await tgCall(token, "sendMessage", { chat_id: message.chat.id, text: `Не получилось войти: ${insertError.message}` })
      return new Response("ok")
    }

    await tgCall(token, "sendMessage", {
      chat_id: message.chat.id,
      text: "✅ Вход подтверждён — возвращайтесь в приложение Forma.",
    })

    return new Response("ok")
  } catch (e) {
    return new Response(String(e), { status: 500 })
  }
})
