# Health Dashboard (static page)

Эта страница (`index.html`) — SPA дашборда, публикуется на GitHub Pages.
Данные и архив грузятся из Supabase после ввода пароля.

## Бэкенд (Supabase)

Исходники бэкенда теперь под версионным контролем в этом репозитории:

- `supabase/functions/health-dashboard/index.ts` — Edge Function (единый POST-эндпоинт:
  вход по паролю с throttle по IP, выдача данных, лог реакций, загрузка/удаление документов).
  Деплой: `supabase functions deploy health-dashboard --no-verify-jwt`.
- `supabase/migrations/` — DDL-миграции (напр. таблица `auth_throttle` для защиты от перебора).
- `supabase/data-fixes/` — разовые правки данных с описанием и откатом.
