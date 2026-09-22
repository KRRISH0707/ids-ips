import { NextResponse } from 'next/server';

export function middleware(request) {
  const { pathname } = request.nextUrl;

  // Allow static assets, next internal files, and favicon
  if (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/static') ||
    pathname.startsWith('/favicon.ico') ||
    pathname.includes('.')
  ) {
    return NextResponse.next();
  }

  // Public pages that do not require authentication
  if (
    pathname.startsWith('/login') ||
    pathname.startsWith('/landing') ||
    pathname.startsWith('/demo') ||
    pathname.startsWith('/api')
  ) {
    return NextResponse.next();
  }

  // Check for authentication cookie
  const token = request.cookies.get('ids_token')?.value;

  // If no auth token cookie, redirect immediately to login page
  if (!token) {
    const loginUrl = new URL('/login', request.url);
    // Preserve the original destination as a redirect query param if useful
    loginUrl.searchParams.set('redirect', pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
