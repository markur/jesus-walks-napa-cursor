import { useStripe, Elements, PaymentElement, useElements } from '@stripe/react-stripe-js';
import { loadStripe, StripeError, PaymentIntentResult, Stripe, StripeElements } from '@stripe/stripe-js';
import { useState, useEffect } from 'react';
import { useCart } from "@/hooks/use-cart";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { MainLayout } from "@/components/layouts/MainLayout";
import { Input } from "@/components/ui/input";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Loader2, AlertCircle, TruckIcon } from "lucide-react";
import { Link, useLocation } from "wouter";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";

if (!import.meta.env.VITE_STRIPE_PUBLIC_KEY) {
  throw new Error('Missing required Stripe key: VITE_STRIPE_PUBLIC_KEY');
}

const stripePromise = loadStripe(import.meta.env.VITE_STRIPE_PUBLIC_KEY);

interface PaymentChangeEvent {
  error?: {
    type?: string;
    message: string;
  };
  complete?: boolean;
  empty?: boolean;
}

interface Address {
  firstName: string;
  lastName: string;
  address1: string;
  city: string;
  state: string;
  postalCode: string;
  country: string;
  phone: string;
}

interface ParcelDetails {
  weight: number;
  length: number;
  width: number;
  height: number;
}

const billingSchema = z.object({
  name: z.string()
    .min(2, "Name must be at least 2 characters")
    .max(50, "Name cannot exceed 50 characters")
    .regex(/^[a-zA-Z\s]*$/, "Name can only contain letters and spaces"),
  email: z.string()
    .email("Please enter a valid email address")
    .min(5, "Email must be at least 5 characters")
    .max(50, "Email cannot exceed 50 characters"),
});

type BillingForm = z.infer<typeof billingSchema>;

// Update ShippingRate type to match the actual API response
interface ShippingRate {
  id: number;
  methodId: number;
  zoneId: number;
  carrier: string;
  service: string;
  baseRate: string;
  perWeightRate: string | null;
  minimumWeight: string | null;
  maximumWeight: string | null;
  estimatedDays: number;
  rate: number;
}

function CheckoutForm() {
  const stripe = useStripe() as Stripe | null;
  const elements = useElements() as StripeElements | null;
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [paymentError, setPaymentError] = useState<string | null>(null);
  const [shippingRates, setShippingRates] = useState<ShippingRate[]>([]);
  const [selectedRate, setSelectedRate] = useState<ShippingRate | null>(null);
  const { toast } = useToast();
  const { state: { total, items }, clearCart } = useCart();
  const [, setLocation] = useLocation();

  const form = useForm<BillingForm>({
    resolver: zodResolver(billingSchema),
    mode: "onChange",
  });

  // Load shipping rates on component mount
  useEffect(() => {
    const loadShippingRates = async () => {
      try {
        const fromAddress: Address = {
          firstName: "Store",
          lastName: "Admin",
          address1: "1234 Store St",
          city: "Napa",
          state: "CA",
          postalCode: "94559",
          country: "US",
          phone: "1234567890"
        };

        const toAddress: Address = {
          firstName: "Customer",
          lastName: "Name",
          address1: "Customer Address",
          city: "Customer City",
          state: "CA",
          postalCode: "90210",
          country: "US",
          phone: "1234567890"
        };

        const parcelDetails: ParcelDetails = {
          weight: 1.0,
          length: 12.0,
          width: 8.0,
          height: 6.0
        };

        const response = await apiRequest("POST", "/api/shipping/calculate-rates", {
          fromAddress,
          toAddress,
          parcelDetails
        });

        if (!response.ok) {
          throw new Error('Failed to fetch shipping rates');
        }

        const rates = await response.json() as ShippingRate[];
        setShippingRates(rates);

        if (rates.length > 0) {
          setSelectedRate(rates[0]);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Failed to load shipping rates';
        toast({
          title: "Error Loading Shipping Rates",
          description: errorMessage,
          variant: "destructive",
        });
      }
    };

    loadShippingRates();
  }, [toast]);

  const handlePaymentChange = (event: StripePaymentElementChangeEvent): void => {
    if (event.error) {
      setPaymentError(event.error.message || 'An unknown error occurred');
    } else {
      setPaymentError(null);
    }
  };

  const handleSubmit = async (data: BillingForm): Promise<void> => {
    if (!stripe || !elements || !selectedRate) {
      return;
    }

    setIsProcessing(true);
    setPaymentError(null);

    try {
      const result = await stripe.confirmPayment({
        elements,
        confirmParams: {
          return_url: `${window.location.origin}/order-confirmation`,
          payment_method_data: {
            billing_details: {
              name: data.name,
              email: data.email,
            }
          },
        },
      });

      if (result.error) {
        throw result.error;
      }

      clearCart();
      setLocation('/order-confirmation');
    } catch (err) {
      const error = err as StripeError;
      setPaymentError(error.message ?? 'An unknown error occurred');
      toast({
        title: "Payment Failed",
        description: error.message || "Please check your details and try again.",
        variant: "destructive",
      });
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-6">
        <div>
          <h2 className="text-lg font-semibold mb-4">Shipping Method</h2>
          <Card>
            <CardContent className="pt-6">
              <div className="space-y-4">
                {shippingRates.map((rate) => (
                  <div
                    key={`${rate.carrier}-${rate.service}`}
                    className={`p-4 border rounded-lg cursor-pointer flex items-center justify-between ${
                      selectedRate?.service === rate.service ? 'border-primary bg-primary/5' : ''
                    }`}
                    onClick={() => setSelectedRate(rate)}
                  >
                    <div className="flex items-center space-x-4">
                      <TruckIcon className="h-5 w-5" />
                      <div>
                        <p className="font-medium">{rate.carrier} - {rate.service}</p>
                        <p className="text-sm text-muted-foreground">
                          Estimated delivery: {rate.estimatedDays} days
                        </p>
                      </div>
                    </div>
                    <p className="font-semibold">${rate.rate.toFixed(2)}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        <div>
          <h2 className="text-lg font-semibold mb-4">Payment Information</h2>
          <Card>
            <CardContent className="pt-6 space-y-4">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Full Name</FormLabel>
                    <FormControl>
                      <Input 
                        {...field} 
                        placeholder="John Doe"
                        className={form.formState.errors.name ? "border-red-500" : ""}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Email</FormLabel>
                    <FormControl>
                      <Input 
                        type="email" 
                        {...field} 
                        placeholder="john@example.com"
                        className={form.formState.errors.email ? "border-red-500" : ""}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <PaymentElement 
                onChange={handlePaymentChange}
                options={{
                  layout: {
                    type: 'tabs',
                    defaultCollapsed: false,
                  }
                }} 
              />

              {paymentError && (
                <div className="flex items-center gap-2 text-red-500 text-sm">
                  <AlertCircle className="h-4 w-4" />
                  <span>{paymentError}</span>
                </div>
              )}

              <div className="pt-4 border-t">
                <div className="flex justify-between text-sm mb-2">
                  <span>Subtotal</span>
                  <span>${total.toFixed(2)}</span>
                </div>
                <div className="flex justify-between text-sm mb-2">
                  <span>Shipping</span>
                  <span>${selectedRate?.rate.toFixed(2) || '0.00'}</span>
                </div>
                <div className="flex justify-between font-semibold text-lg">
                  <span>Total</span>
                  <span>${(total + (selectedRate?.rate || 0)).toFixed(2)}</span>
                </div>
              </div>

              <Button 
                type="submit" 
                className="w-full" 
                disabled={isProcessing || !stripe || !form.formState.isValid}
              >
                {isProcessing ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Processing...
                  </>
                ) : (
                  `Pay $${(total + (selectedRate?.rate || 0)).toFixed(2)}`
                )}
              </Button>
            </CardContent>
          </Card>
        </div>
      </form>
    </Form>
  );
}

export default function Checkout() {
  const [clientSecret, setClientSecret] = useState<string>("");
  const { state: { total, items } } = useCart();

  // Create payment intent when component mounts
  useEffect(() => {
    if (items.length > 0) {
      apiRequest("POST", "/api/create-payment-intent", { amount: total })
        .then((res) => res.json())
        .then((data) => setClientSecret(data.clientSecret))
        .catch((error) => {
          console.error("Failed to create payment intent:", error);
        });
    }
  }, [total, items]);

  if (items.length === 0) {
    return (
      <MainLayout>
        <div className="container mx-auto px-4 py-8">
          <div className="max-w-2xl mx-auto">
            <Card>
              <CardContent className="p-8 text-center">
                <p className="text-muted-foreground mb-6">Your cart is empty</p>
                <Link href="/shop">
                  <Button>Continue Shopping</Button>
                </Link>
              </CardContent>
            </Card>
          </div>
        </div>
      </MainLayout>
    );
  }

  if (!clientSecret) {
    return (
      <MainLayout>
        <div className="container mx-auto px-4 py-8">
          <div className="max-w-2xl mx-auto">
            <Card>
              <CardContent className="flex justify-center p-4">
                <Loader2 className="h-8 w-8 animate-spin" />
              </CardContent>
            </Card>
          </div>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-2xl mx-auto">
          <Card>
            <CardContent>
              <Elements stripe={stripePromise} options={{ 
                clientSecret,
                appearance: {
                  theme: 'stripe',
                }
              }}>
                <CheckoutForm />
              </Elements>
            </CardContent>
          </Card>
        </div>
      </div>
    </MainLayout>
  );
}