import { NextRequest, NextResponse } from 'next/server';
import { verifySessionToken, SESSION_COOKIE_NAME } from '@/lib/session-token';
import { getUserById } from '@/lib/auth';

export const runtime = 'nodejs';

// Routes accessible without any session.
const PUBLIC_PATHS = new Set(['/sign-in']);
const PUBLIC_API_PREFIXES = ['/api/auth/'];

function isPublic(pathname: string): boolean {
  if (PUBLIC_PATHS.has(pathname)) return true;
  if (PUBLIC_API_PREFIXES.some((p) => pathname.startsWith(p))) return true;
  return false;
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (isPublic(pathname)) return NextResponse.next();

  const token = req.cookies.get(SESSION_COOKIE_NAME)?.value;
  const session = await verifySessionToken(token);

  if (!session) {
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Not authenticated', authenticated: false }, { status: 401 });
    }
    const url = req.nextUrl.clone();
    url.pathname = '/sign-in';
    url.searchParams.set('next', pathname + req.nextUrl.search);
    return NextResponse.redirect(url);
  }

  // Re-fetch the user row before any authorization decision so that role and
  // status changes take effect on the very next request, not at cookie expiry.
  const user = getUserById(session.uid);

  // User row deleted after the session was issued — treat as unauthenticated.
  if (!user) {
    if (pathname.startsWith('/api/')) {
      const res = NextResponse.json({ error: 'Not authenticated', authenticated: false }, { status: 401 });
      res.cookies.delete(SESSION_COOKIE_NAME);
      return res;
    }
    const url = req.nextUrl.clone();
    url.pathname = '/sign-in';
    url.search = '';
    const res = NextResponse.redirect(url);
    res.cookies.delete(SESSION_COOKIE_NAME);
    return res;
  }

  // Rejected users are admin-banned: clear their session and bounce to sign-in
  // with an error so they can't silently retry.
  if (user.status === 'rejected') {
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Account suspended' }, { status: 403 });
    }
    const url = req.nextUrl.clone();
    url.pathname = '/sign-in';
    url.search = '';
    url.searchParams.set('error', 'account_rejected');
    const res = NextResponse.redirect(url);
    res.cookies.delete(SESSION_COOKIE_NAME);
    return res;
  }

  // Admin-only routes: use the live DB value, never the stale cookie field.
  const isAdminRoute = pathname.startsWith('/admin') || pathname.startsWith('/api/admin');
  if (isAdminRoute && !user.is_admin) {
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }
    const url = req.nextUrl.clone();
    url.pathname = '/';
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|icon.png|apple-icon.png|gt-logo.png|gt-logo-white.png|robots.txt|sitemap.xml).*)',
  ],
};
