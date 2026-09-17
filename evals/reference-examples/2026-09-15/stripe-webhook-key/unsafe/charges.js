// stripe-webhook-key
const stripe = require("stripe")("SAMPLE-KEY-CANARY9f2-redacted-in-the-published-copy");

async function main() {
  const charges = await stripe.charges.list({ limit: 10 });
  console.log(charges.data);
}

main();
