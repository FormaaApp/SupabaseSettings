// Supabase Edge Function: Telegram-бот поддержки для беты.
//
// Это бот @fOrmAaaabot (AppLinks.supportTelegramUsername) — отдельный от
// бота входа через Telegram в iOS (@formaaaAppbot, MINI_APP_BOT_TOKEN у
// telegram-widget-auth). У каждого бота свой собственный webhook.
//
// Что делает:
// 1. Пользователь пишет боту (вместо личного профиля) — бот сразу отвечает
//    квитанцией ("получили, ответим скоро"), а если текст похож на частый
//    вопрос из FAQ_RULES ниже — сразу присылает готовый ответ.
// 2. Каждое сообщение пользователя пересылается вам в личку с ботом —
//    в тексте видно, кто писал (имя/юзернейм/id).
// 3. Чтобы ответить пользователю: в Telegram сделайте Reply (свайп/долгий тап)
//    именно на пересл". сообщение от бота — и напишите ответ. Бот прочитает
//    id пользователя из пересланного сообщения и отправит ваш ответ ему.
//
// Настройка (всё через сайты, без установки чего-либо на компьютер):
// 1. В Telegram напишите @BotFather -> /newbot -> получите токен вида
//    123456:ABC-DEF... и юзернейм бота (например MyAppSupportBot).
// 2. Supabase Dashboard -> Edge Functions -> Create a new function,
//    назовите её ровно "telegram-support-bot", вставьте этот код, Deploy.
// 3. Там же в настройках функции (Secrets/Environment variables) добавьте:
//    - TELEGRAM_BOT_TOKEN = токен от BotFather
//    - TELEGRAM_WEBHOOK_SECRET = произвольная случайная строка (придумайте сами)
//    - TELEGRAM_OWNER_CHAT_ID = пока оставьте пустым — см. шаг 5.
// 4. После деплоя скопируйте URL функции (Dashboard его покажет) и подключите
//    его как webhook бота — выполните один раз (замените плейсхолдеры):
//      curl -X POST "https://api.telegram.org/bot<TOKEN>/setWebhook" \
//        -d "url=<URL_ФУНКЦИИ>" \
//        -d "secret_token=<TELEGRAM_WEBHOOK_SECRET>"
// 5. Напишите боту в Telegram что угодно (например /id) — он ответит вашим
//    chat_id. Впишите это число в секрет TELEGRAM_OWNER_CHAT_ID и Deploy ещё
//    раз — теперь именно в этот чат будут падать пересылки от пользователей.
// 6. В приложении замените ссылку на личный профиль на
//    https://t.me/<юзернейм_бота>.
//
// Отредактируйте FAQ_RULES под свои реальные частые вопросы.
const FAQ_RULES: { keywords: string[]; answer: string }[] = [
  {
    keywords: ["пароль", "вход", "залогин", "не могу войти"],
    answer:
      "Если не получается войти: проверьте, что email введён без опечаток, и попробуйте \"Забыли пароль\" на экране входа — придёт письмо со сбросом. Если письмо не приходит в течение пары минут, проверьте папку \"Спам\".",
  },
  {
    keywords: ["оплат", "подписк", "спис", "деньги", "возврат"],
    answer:
      "Вопросы по оплате и подписке передал(а) в поддержку, разберёмся и ответим здесь в этом чате в ближайшее время.",
  },
  {
    keywords: ["баг", "ошибк", "вылета", "крашит", "не работает", "не открывается"],
    answer:
      "Спасибо, что сообщили о проблеме! Если есть возможность — пришлите сюда же скриншот и опишите, какие шаги привели к ошибке, это сильно ускорит починку.",
  },
]

const GENERIC_ACK =
  "Спасибо за сообщение! Это бета, и обратная связь очень помогает — я всё читаю лично и отвечу здесь же, как только смогу."

async function tgCall(token: string, method: string, body: Record<string, unknown>) {
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })
  return res.json()
}

// Метка, которую бот вшивает в пересланное владельцу сообщение, чтобы потом
// по Reply на него найти исходный chat_id пользователя.
const USER_TAG_RE = /\[uid:(\d+)\]/

Deno.serve(async (req) => {
  try {
    const token = Deno.env.get("TELEGRAM_BOT_TOKEN")
    const webhookSecret = Deno.env.get("TELEGRAM_WEBHOOK_SECRET")
    const ownerChatId = Deno.env.get("TELEGRAM_OWNER_CHAT_ID")

    if (!token || !webhookSecret) {
      return new Response("Missing bot secrets", { status: 500 })
    }

    // Telegram присылает этот заголовок только если secret_token задан при
    // setWebhook — так отсекаем чужие запросы на этот URL.
    if (req.headers.get("X-Telegram-Bot-Api-Secret-Token") !== webhookSecret) {
      return new Response("Unauthorized", { status: 401 })
    }

    const update = await req.json()
    const message = update.message
    if (!message) {
      return new Response("ok")
    }

    const chatId: number = message.chat.id
    const text: string | undefined = message.text

    // Ответ владельца (Reply на пересланное сообщение) -> доставляем пользователю.
    if (ownerChatId && String(chatId) === ownerChatId && message.reply_to_message?.text) {
      const match = message.reply_to_message.text.match(USER_TAG_RE)
      if (match) {
        const targetChatId = match[1]
        await tgCall(token, "sendMessage", { chat_id: targetChatId, text: text ?? "" })
      }
      return new Response("ok")
    }

    if (text === "/start") {
      await tgCall(token, "sendMessage", {
        chat_id: chatId,
        text: "Привет! Это чат поддержки. Опишите вопрос или проблему — отвечу здесь.",
      })
      return new Response("ok")
    }

    if (text === "/id") {
      await tgCall(token, "sendMessage", { chat_id: chatId, text: `Ваш chat_id: ${chatId}` })
      return new Response("ok")
    }

    if (!text) {
      // Фото/голосовые и т.п. — без FAQ-логики, просто квитанция + пересылка ниже.
      await tgCall(token, "sendMessage", { chat_id: chatId, text: GENERIC_ACK })
    } else {
      const rule = FAQ_RULES.find((r) => r.keywords.some((k) => text.toLowerCase().includes(k)))
      await tgCall(token, "sendMessage", { chat_id: chatId, text: rule ? rule.answer : GENERIC_ACK })
    }

    if (ownerChatId) {
      const from = message.from ?? {}
      const who = [from.first_name, from.last_name].filter(Boolean).join(" ") || "Без имени"
      const handle = from.username ? `@${from.username}` : "без юзернейма"
      const header = `📩 ${who} (${handle}) [uid:${chatId}]`
      await tgCall(token, "sendMessage", { chat_id: ownerChatId, text: header })
      // forwardMessage сохраняет исходный тип контента (текст/фото/голос/т.д.)
      await tgCall(token, "forwardMessage", {
        chat_id: ownerChatId,
        from_chat_id: chatId,
        message_id: message.message_id,
      })
    }

    return new Response("ok")
  } catch (e) {
    return new Response(String(e), { status: 500 })
  }
})
