// admin-users: lets a signed-in admin manage admin accounts (username + password).
// Runs with the project's secret key, so it never reaches the browser.
// Every action requires a valid session whose user is listed in public.admins.
import { createClient } from 'npm:@supabase/supabase-js@2';

// Usernames are stored as Supabase Auth users with a placeholder email on a reserved,
// undeliverable domain. Keep this in sync with usernameDomain in /js/config.js.
const EMAIL_DOMAIN = 'admin.bisianumu.invalid';
const USERNAME = /^[a-z0-9._-]{3,32}$/;

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-client-info',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

function secretKey(): string {
  try {
    const keys = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') || '{}');
    if (keys.default) return keys.default;
  } catch (_) { /* fall through to the legacy variable */ }
  return Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
}

const admin = createClient(Deno.env.get('SUPABASE_URL')!, secretKey(), {
  auth: { persistSession: false, autoRefreshToken: false },
});

async function callerIfAdmin(req: Request) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (!token) return null;
  const { data, error } = await admin.auth.getUser(token);
  if (error || !data.user) return null;
  const { data: row } = await admin.from('admins').select('user_id').eq('user_id', data.user.id).maybeSingle();
  return row ? data.user : null;
}

function passwordProblem(pw: unknown): string | null {
  if (typeof pw !== 'string' || pw.length < 10) return 'Password must be at least 10 characters.';
  if (pw.length > 72) return 'Password must be 72 characters or fewer.';
  return null;
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return json({ error: 'Method not allowed.' }, 405);

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch (_) { return json({ error: 'Invalid request.' }, 400); }

  const me = await callerIfAdmin(req);
  if (!me) return json({ error: 'Not allowed. Please sign in again.' }, 401);

  switch (body.action) {
    case 'list': {
      const { data: rows, error } = await admin.from('admins').select('user_id,username,created_at').order('created_at');
      if (error) return json({ error: 'Could not load admins.' }, 500);
      const out = [];
      for (const r of rows ?? []) {
        const { data } = await admin.auth.admin.getUserById(r.user_id);
        const email = data?.user?.email ?? '';
        out.push({
          user_id: r.user_id,
          username: r.username,
          email: email.endsWith('@' + EMAIL_DOMAIN) ? null : email,
          created_at: r.created_at,
          is_self: r.user_id === me.id,
        });
      }
      return json({ admins: out });
    }

    case 'create': {
      const username = String(body.username ?? '').trim().toLowerCase();
      if (!USERNAME.test(username)) return json({ error: 'Username must be 3 to 32 characters: letters, numbers, dot, dash or underscore.' }, 400);
      const problem = passwordProblem(body.password);
      if (problem) return json({ error: problem }, 400);
      const { data: taken } = await admin.from('admins').select('user_id').eq('username', username).maybeSingle();
      if (taken) return json({ error: 'That username is already taken.' }, 409);
      const { data, error } = await admin.auth.admin.createUser({
        email: `${username}@${EMAIL_DOMAIN}`,
        password: body.password as string,
        email_confirm: true,
        user_metadata: { username },
      });
      if (error || !data.user) return json({ error: error?.message || 'Could not create the account.' }, 400);
      const { error: insertError } = await admin.from('admins').insert({ user_id: data.user.id, username });
      if (insertError) {
        await admin.auth.admin.deleteUser(data.user.id);
        return json({ error: 'Could not save the admin record.' }, 500);
      }
      return json({ ok: true, username });
    }

    case 'set_password': {
      const id = String(body.user_id ?? '');
      const problem = passwordProblem(body.password);
      if (problem) return json({ error: problem }, 400);
      const { data: target } = await admin.from('admins').select('user_id').eq('user_id', id).maybeSingle();
      if (!target) return json({ error: 'That admin was not found.' }, 404);
      const { error } = await admin.auth.admin.updateUserById(id, { password: body.password as string });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }

    case 'delete': {
      const id = String(body.user_id ?? '');
      if (id === me.id) return json({ error: 'You cannot remove your own account.' }, 400);
      const { data: target } = await admin.from('admins').select('user_id').eq('user_id', id).maybeSingle();
      if (!target) return json({ error: 'That admin was not found.' }, 404);
      const { count } = await admin.from('admins').select('user_id', { count: 'exact', head: true });
      if ((count ?? 0) <= 1) return json({ error: 'You cannot remove the last admin.' }, 400);
      const { error: delRow } = await admin.from('admins').delete().eq('user_id', id);
      if (delRow) return json({ error: 'Could not remove the admin.' }, 500);
      const { error: delUser } = await admin.auth.admin.deleteUser(id);
      if (delUser) return json({ error: delUser.message }, 400);
      return json({ ok: true });
    }

    default:
      return json({ error: 'Unknown action.' }, 400);
  }
});
