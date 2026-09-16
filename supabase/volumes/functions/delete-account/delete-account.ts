// Supabase Edge Function: полное удаление аккаунта.
//
// Почему это не может жить в самом приложении: чтобы удалить сам логин
// (auth.users), нужен service_role key — ключ с полными правами. Его
// НЕЛЬЗЯ класть в iOS-приложение (кто угодно мог бы его достать из бинарника
// и получить полный доступ к базе). Поэтому это отдельная серверная функция,
// которая живёт в Supabase, а не в приложении.
//
// Как задеплоить (без установки чего-либо на компьютер):
// 1. Supabase Dashboard -> Edge Functions -> Create a new function.
// 2. Назови её ровно "delete-account".
// 3. Вставь этот код целиком.
// 4. Deploy. SUPABASE_URL / SUPABASE_ANON_KEY / SUPABASE_SERVICE_ROLE_KEY
//    подставляются автоматически — их не нужно вписывать самому.
// 5. После деплоя Dashboard покажет URL функции — он понадобится в приложении.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

Deno.serve(async (req) => {
  try {
    const authHeader = req.headers.get("Authorization")
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "No authorization header" }), { status: 401 })
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!

    // Клиент от имени самого вызывающего — чтобы точно знать, кто он, и
    // чтобы RPC ниже сработала именно для его auth.uid(), а не для кого-то ещё.
    const userClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    })

    const { data: { user }, error: userError } = await userClient.auth.getUser()
    if (userError || !user) {
      // Раньше здесь временно отдавался detail: userError?.message — на
      // время диагностики ключевого рассинхрона SUPABASE_ANON_KEY. Причина
      // найдена и не повторяется — светить внутренний текст ошибки
      // авторизации любому вызывающему с невалидным токеном больше незачем.
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 })
    }

    // 1. Стираем все строки пользователя в базе — RPC сама проверяет
    //    auth.uid() внутри себя (подделать чужой id нельзя) и возвращает
    //    пути к файлам в Storage, которые тоже нужно удалить: Supabase
    //    больше не разрешает удалять сами файлы прямым SQL DELETE.
    const { data: paths, error: wipeError } = await userClient.rpc("delete_own_account_data")
    if (wipeError) {
      return new Response(JSON.stringify({ error: wipeError.message }), { status: 400 })
    }

    // 2. Сервисным ключом (доступен только здесь, не в приложении) стираем
    //    сами файлы через Storage API и удаляем сам логин.
    const adminClient = createClient(supabaseUrl, serviceRoleKey)

    // НАЙДЕНО при аудите бэкенда (2026-09-16): .remove() раньше вызывался
    // без проверки результата — неудачное удаление файлов (сеть, права,
    // уже отсутствующий бакет) проходило незамеченным, и файлы оставались
    // висеть в Storage НАВСЕГДА, хотя сам аккаунт и все строки в БД уже
    // удалены — никакого способа найти и дочистить их позже уже не было бы
    // (сама строка, которая на них указывала, тоже стёрта). Теперь неудачи
    // собираются и попадают в ответ — не блокируют само удаление аккаунта
    // (данные и логин всё равно нужно снести), но хотя бы не молчат.
    const storageFailures: string[] = []
    if (paths && typeof paths === "object") {
      for (const bucket of Object.keys(paths)) {
        const files = paths[bucket]
        if (Array.isArray(files) && files.length > 0) {
          const { error: removeError } = await adminClient.storage.from(bucket).remove(files)
          if (removeError) {
            storageFailures.push(`${bucket}: ${removeError.message}`)
          }
        }
      }
    }

    const { error: deleteError } = await adminClient.auth.admin.deleteUser(user.id)
    if (deleteError) {
      return new Response(JSON.stringify({ error: deleteError.message }), { status: 400 })
    }

    return new Response(
      JSON.stringify({ success: true, storageFailures: storageFailures.length > 0 ? storageFailures : undefined }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    )
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), { status: 500 })
  }
})
