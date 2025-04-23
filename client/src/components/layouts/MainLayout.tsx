import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { Menu, Facebook, Instagram, Twitter, ShoppingCart } from "lucide-react";
import { useIsMobile } from "@/hooks/use-mobile";
import { useQuery } from "@tanstack/react-query";
import { useCart } from "@/hooks/use-cart";
import type { User } from "@shared/schema";

// Social media configuration
const SOCIAL_LINKS = {
  facebook: "https://www.facebook.com/jesuswalks.community",
  instagram: "https://www.instagram.com/jesuswalksnapa",
  twitter: "https://twitter.com/jesuswalks_com",
};

interface MainLayoutProps {
  children: React.ReactNode;
}

export function MainLayout({ children }: MainLayoutProps) {
  const isMobile = useIsMobile();
  const { data: user } = useQuery<User | null>({
    queryKey: ["/api/auth/me"],
  });
  const { state: { items } } = useCart();
  const cartItemsCount = items.reduce((total, item) => total + item.quantity, 0);

  const NavLinks = () => (
    <>
      <Link href="/events">
        <Button variant="ghost">Events</Button>
      </Link>
      <Link href="/shop">
        <Button variant="ghost">Shop</Button>
      </Link>
      <Link href="/cart">
        <Button variant="ghost" className="relative">
          <ShoppingCart className="h-5 w-5" />
          {cartItemsCount > 0 && (
            <span className="absolute -top-1 -right-1 bg-primary text-primary-foreground rounded-full w-5 h-5 text-xs flex items-center justify-center">
              {cartItemsCount}
            </span>
          )}
        </Button>
      </Link>
      {user ? (
        <>
          {user.isAdmin && (
            <Link href="/admin">
              <Button variant="ghost">Admin Panel</Button>
            </Link>
          )}
          <Link href="/logout">
            <Button variant="ghost">Logout</Button>
          </Link>
        </>
      ) : (
        <>
          <Link href="/login">
            <Button variant="ghost">Login</Button>
          </Link>
          <Link href="/register">
            <Button>Join Now</Button>
          </Link>
        </>
      )}
    </>
  );

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <Link href="/">
            <span className="text-2xl md:text-3xl font-bold font-serif tracking-wide">Jesus Walks Napa</span>
          </Link>

          {isMobile ? (
            <Sheet>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon">
                  <Menu className="h-5 w-5" />
                </Button>
              </SheetTrigger>
              <SheetContent>
                <div className="flex flex-col gap-4 mt-8">
                  <NavLinks />
                </div>
              </SheetContent>
            </Sheet>
          ) : (
            <nav className="flex items-center gap-4">
              <NavLinks />
            </nav>
          )}
        </div>
      </header>

      <main className="flex-1">{children}</main>

      <footer className="border-t py-8 mt-16">
        <div className="container mx-auto px-4 text-center">
          <div className="flex justify-center gap-6 mb-4">
            <a
              href={SOCIAL_LINKS.facebook}
              target="_blank"
              rel="noopener noreferrer"
              className="text-muted-foreground hover:text-primary transition-colors"
              title="Follow us on Facebook"
            >
              <Facebook className="h-6 w-6" />
              <span className="sr-only">Facebook</span>
            </a>
            <a
              href={SOCIAL_LINKS.instagram}
              target="_blank"
              rel="noopener noreferrer"
              className="text-muted-foreground hover:text-primary transition-colors"
              title="Follow us on Instagram"
            >
              <Instagram className="h-6 w-6" />
              <span className="sr-only">Instagram</span>
            </a>
            <a
              href={SOCIAL_LINKS.twitter}
              target="_blank"
              rel="noopener noreferrer"
              className="text-muted-foreground hover:text-primary transition-colors"
              title="Follow us on Twitter"
            >
              <Twitter className="h-6 w-6" />
              <span className="sr-only">Twitter</span>
            </a>
          </div>
          <p className="text-sm text-muted-foreground">© 2024 Jesus Walks. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}