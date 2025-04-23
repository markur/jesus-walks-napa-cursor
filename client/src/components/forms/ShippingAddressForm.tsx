import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Card, CardContent } from "@/components/ui/card";
import { Loader2, CheckCircle } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { shippingAddressSchema, type ShippingAddress } from "@shared/schema";

type ShippingFormProps = {
  onAddressValidated: (address: ShippingAddress) => void;
};

export function ShippingAddressForm({ onAddressValidated }: ShippingFormProps) {
  const [isValidating, setIsValidating] = useState(false);
  const [isAddressValid, setIsAddressValid] = useState(false);

  const form = useForm<ShippingAddress>({
    resolver: zodResolver(shippingAddressSchema),
    mode: "onChange",
  });

  const validateAddress = async (data: ShippingAddress) => {
    setIsValidating(true);
    try {
      const response = await apiRequest("POST", "/api/shipping/validate-address", data);
      const validatedAddress = await response.json();
      
      if (validatedAddress.isValid) {
        setIsAddressValid(true);
        onAddressValidated(validatedAddress.normalizedAddress || data);
      } else {
        form.setError("address1", {
          type: "manual",
          message: validatedAddress.messages?.[0] || "Invalid address"
        });
        setIsAddressValid(false);
      }
    } catch (error: any) {
      form.setError("address1", {
        type: "manual",
        message: error.message || "Failed to validate address"
      });
      setIsAddressValid(false);
    } finally {
      setIsValidating(false);
    }
  };

  return (
    <Card>
      <CardContent className="pt-6">
        <Form {...form}>
          <form onSubmit={form.handleSubmit(validateAddress)} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="firstName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>First Name</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="John" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="lastName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Last Name</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="Doe" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <FormField
              control={form.control}
              name="address1"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Address Line 1</FormLabel>
                  <FormControl>
                    <Input {...field} placeholder="123 Main St" />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="address2"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Address Line 2 (Optional)</FormLabel>
                  <FormControl>
                    <Input {...field} placeholder="Apt, Suite, etc." />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="city"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>City</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="City" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="state"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>State</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="CA" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="postalCode"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Postal Code</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="12345" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="phone"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Phone Number</FormLabel>
                    <FormControl>
                      <Input {...field} type="tel" placeholder="(123) 456-7890" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <Button 
              type="submit" 
              className="w-full"
              disabled={isValidating || !form.formState.isValid}
            >
              {isValidating ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Validating Address...
                </>
              ) : isAddressValid ? (
                <>
                  <CheckCircle className="mr-2 h-4 w-4" />
                  Address Verified
                </>
              ) : (
                'Validate Address'
              )}
            </Button>
          </form>
        </Form>
      </CardContent>
    </Card>
  );
}
