// stripe-webhook-key
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

async function main() {
  if (!process.env.STRIPE_SECRET_KEY) {
    throw new Error("Set STRIPE_SECRET_KEY in the environment before running this.");
  }
  const charges = await stripe.charges.list({ limit: 10 });
  console.log(charges.data);
}

main();
