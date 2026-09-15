# SupabaseBackend

## Описание

Основной бекенд сервис для работы мобильного приложения [KBJUCouchApp](https://github.com/FormaaApp/KBJUCouchApp).

## Начало работы

1. В директорию `supabase/` поместить все файлы, которые должны быть на сервере. Учтите, **все** файлы из `supabase/*` перезаписывают существующие, кроме папок `volumes/` и `migrations/`. `migrations/` игнорируются, а в `volumes/` заменяется только `functions/` и больше ничего.
2. В `migrations/` поместите миграции для `PostgreSQL`.
