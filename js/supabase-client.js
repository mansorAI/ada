const SUPABASE_URL = 'https://xnfzttjnwkfznxvohngy.supabase.co';
const SUPABASE_KEY = 'sb_publishable_nUDdwuF5r5KdA78CYm2hGA_R5gvLzha';
const sb = supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

let currentUser = null;
let currentProfile = null;
let currentGroupId = null;

async function requireAuth() {
  const { data } = await sb.auth.getSession();
  if (!data.session) {
    window.location.href = 'index.html';
    return null;
  }
  currentUser = data.session.user;

  const { data: profile } = await sb.from('profiles').select('*').eq('id', currentUser.id).single();
  currentProfile = profile;
  return data.session;
}

async function signOut() {
  await sb.auth.signOut();
  window.location.href = 'index.html';
}

function getMonthKey(date = new Date()) {
  return `${date.getFullYear()}-${date.getMonth() + 1}`;
}

async function auditLog(groupId, action, entityType, entityName, details = {}) {
  if (!currentUser) return;
  await sb.from('audit_log').insert({
    group_id: groupId,
    user_id: currentUser.id,
    user_email: currentUser.email,
    user_name: currentProfile?.name || '',
    action,
    entity_type: entityType,
    entity_name: entityName,
    details
  });
}
