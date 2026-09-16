// Supabase Edge Function: опрос статуса device-flow входа через Telegram
// (см. telegram-login-bot/index.ts — та функция кладёт сюда готовую сессию
// после того, как пользователь отправил боту 6-значный код из приложения).
//
// iOS вызывает эту функцию каждые ~1.5с с тем же кодом, что показан на
// экране входа (AuthService.signInWithTelegram()). Код сам по себе —
// единственный секрет здесь, поэтому доступ анонимный: строка отдаётся
// ровно тому, кто знает код, и сразу удаляется — второй раз тем же кодом
// её уже не получить.
//
// Настройка:
// 1. Supabase Dashboard -> Edge Functions -> Create a new function,
//    назовите её ровно "telegram-login-poll", вставьте этот код, Deploy.
// 2. В настройках функции выключите "Enforce JWT Verification" — её
//    вызывает клиент без сессии Supabase (это и есть весь смысл функции).
// 3. Secrets: SERVICE_ROLE_KEY (то же значение, что и у telegram-login-bot).
//    SUPABASE_URL подставляется автоматически.
// 4. Прогоните 104_telegram_login_rpc.sql и 149_telegram_login_poll_rate_limit.sql,
//    если ещё не прогоняли.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
}

function json(body: unknown, status: number) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  })
}

// НАЙДЕНО при аудите бэкенда (2026-09-16): ничего не ограничивало, сколько
// раз в секунду можно дёргать эту функцию — код живёт всего 3 минуты
// (131_telegram_login_code_expiry.sql), но за это время без лимита можно
// перебрать заметную долю миллиона возможных 6-значных кодов. Заголовки
// прокси пробуем по очереди — self-host стоит за реверс-прокси, реальный IP
// клиента виден только через X-Forwarded-For/X-Real-IP, "unknown" (общий,
// не персональный лимит) — на случай, если ни один заголовок не дошёл, а не
// полное отсутствие ограничения.
function clientIp(req: Request): string {
  const forwarded = req.headers.get("x-forwarded-for")
  if (forwarded) {
    return forwarded.split(",")[0].trim()
  }
  return req.headers.get("x-real-ip") ?? "unknown"
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders })
  }

  try {
    const { code } = (await req.json()) as { code?: string }
    if (!code) {
      return json({ error: "Missing code" }, 400)
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!
    const serviceRoleKey = Deno.env.get("SERVICE_ROLE_KEY") ?? Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    const admin = createClient(supabaseUrl, serviceRoleKey)

    const { data: allowed, error: rateLimitError } = await admin.rpc("check_and_record_login_poll_attempt", {
      p_ip: clientIp(req),
    })
    // Best-effort — если сам рейт-лимит недоступен (миграция ещё не
    // накатана, RPC упала), не блокируем вход из-за диагностики: это уже
    // не хуже, чем было раньше (без лимита вообще).
    if (!rateLimitError && allowed === false) {
      return json({ error: "Too many attempts, try again in a minute" }, 429)
    }

    // security definer функция (104_telegram_login_rpc.sql) — прямой select
    // из таблицы тоже упирался бы в RLS по той же причине, что и upsert в
    // telegram-login-bot. DELETE ... RETURNING внутри неё атомарно и
    // забирает сессию, и убирает строку — второй опрос с тем же кодом
    // больше ничего не найдёт.
    const { data, error } = await admin.rpc("fetch_and_clear_telegram_login", { p_code: code })

    if (error) {
      return json({ error: error.message }, 500)
    }
    const row = Array.isArray(data) ? data[0] : null
    if (!row) {
      return json({ pending: true }, 200)
    }

    return json({ access_token: row.access_token, refresh_token: row.refresh_token }, 200)
  } catch (e) {
    return json({ error: String(e) }, 500)
  }
})
