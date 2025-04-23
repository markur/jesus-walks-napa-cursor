import { Button } from "@/components/ui/button";
import { Link } from "wouter";

export function Hero() {
  return (
    <div className="relative h-[600px]">
      <div 
        className="absolute inset-0 bg-cover bg-center"
        style={{
          backgroundImage: `url('https://images.unsplash.com/photo-1464823063530-08f10ed1a2dd')`,
          filter: 'brightness(0.5)'
        }}
        role="img"
        aria-label="Scenic vineyard landscape in Napa Valley"
      />

      <div className="relative z-10 container mx-auto px-4 py-24 sm:py-32">
        <div className="max-w-2xl">
          <h1 className="text-4xl font-bold tracking-tight text-white sm:text-6xl font-serif">
            Find Your Path in Faith & Nature
          </h1>
          <p className="mt-6 text-lg leading-8 text-white font-sans font-medium">
            Join a community of believers who share your passion for outdoor adventure
            and spiritual growth. Experience God's creation through guided hikes and
            meaningful connections with Jesus Walks.
          </p>
          <div className="mt-10 flex flex-col sm:flex-row gap-4 sm:gap-x-6">
            <Link href="/register">
              <Button size="lg" className="text-lg w-full sm:w-auto">
                Join Our Community
              </Button>
            </Link>
            <Link href="/events">
              <Button variant="outline" size="lg" className="text-lg w-full sm:w-auto text-white border-white hover:bg-white/10">
                View Events
              </Button>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}