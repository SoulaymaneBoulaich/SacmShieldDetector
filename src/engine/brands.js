// ScamShield Pro - Curated Brand & Domain Registry
// Covers top phishing targets across Financial, Tech, Crypto, E-Commerce, Social Media & Government

const TOP_BRANDS = [
  // Tech & Cloud
  { name: 'Google', domains: ['google.com', 'accounts.google.com', 'gmail.com', 'youtube.com', 'drive.google.com'], keywords: ['google', 'gmail', 'youtube'] },
  { name: 'Microsoft', domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'login.microsoftonline.com', 'azure.com'], keywords: ['microsoft', 'outlook', 'office365', 'onedrive', 'azure'] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com', 'appleid.apple.com'], keywords: ['apple', 'icloud', 'appleid'] },
  { name: 'Amazon', domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'aws.amazon.com'], keywords: ['amazon', 'primevideo', 'aws'] },
  { name: 'Meta', domains: ['meta.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'messenger.com'], keywords: ['facebook', 'instagram', 'whatsapp', 'meta'] },
  { name: 'Netflix', domains: ['netflix.com'], keywords: ['netflix'] },
  { name: 'Spotify', domains: ['spotify.com'], keywords: ['spotify'] },
  { name: 'Adobe', domains: ['adobe.com', 'creativecloud.com'], keywords: ['adobe', 'photoshop', 'creativecloud'] },
  { name: 'Dropbox', domains: ['dropbox.com'], keywords: ['dropbox'] },
  { name: 'GitHub', domains: ['github.com', 'github.io'], keywords: ['github'] },
  { name: 'Twitter/X', domains: ['twitter.com', 'x.com'], keywords: ['twitter'] },
  { name: 'LinkedIn', domains: ['linkedin.com'], keywords: ['linkedin'] },
  { name: 'Yahoo', domains: ['yahoo.com', 'mail.yahoo.com'], keywords: ['yahoo'] },
  { name: 'Steam', domains: ['steampowered.com', 'steamcommunity.com'], keywords: ['steam', 'steampowered', 'steamcommunity'] },
  { name: 'Discord', domains: ['discord.com', 'discord.gg', 'discordapp.com'], keywords: ['discord', 'discordnitro'] },

  // Banking & Fintech
  { name: 'PayPal', domains: ['paypal.com', 'paypal.me', 'paypal-community.com'], keywords: ['paypal', 'pypl'] },
  { name: 'Chase', domains: ['chase.com', 'jpmorganchase.com'], keywords: ['chase', 'jpmorgan'] },
  { name: 'Bank of America', domains: ['bankofamerica.com', 'bofa.com'], keywords: ['bankofamerica', 'bofa'] },
  { name: 'Wells Fargo', domains: ['wellsfargo.com'], keywords: ['wellsfargo'] },
  { name: 'Citigroup', domains: ['citi.com', 'citigroup.com', 'citibank.com'], keywords: ['citibank', 'citigroup'] },
  { name: 'Capital One', domains: ['capitalone.com'], keywords: ['capitalone'] },
  { name: 'Stripe', domains: ['stripe.com', 'dashboard.stripe.com'], keywords: ['stripe'] },
  { name: 'Square / Block', domains: ['squareup.com', 'block.xyz', 'cash.app'], keywords: ['squareup', 'cashapp'] },
  { name: 'Venmo', domains: ['venmo.com'], keywords: ['venmo'] },
  { name: 'Revolut', domains: ['revolut.com'], keywords: ['revolut'] },
  { name: 'Wise', domains: ['wise.com', 'transferwise.com'], keywords: ['wise', 'transferwise'] },
  { name: 'HSBC', domains: ['hsbc.com', 'hsbc.co.uk'], keywords: ['hsbc'] },
  { name: 'Barclays', domains: ['barclays.co.uk', 'barclays.com'], keywords: ['barclays'] },
  { name: 'Santander', domains: ['santander.com', 'santander.co.uk', 'santander.es'], keywords: ['santander'] },
  { name: 'BNP Paribas', domains: ['bnpparibas.com', 'group.bnpparibas'], keywords: ['bnpparibas'] },

  // Crypto & Web3
  { name: 'Binance', domains: ['binance.com', 'binance.us'], keywords: ['binance'] },
  { name: 'Coinbase', domains: ['coinbase.com', 'pro.coinbase.com'], keywords: ['coinbase'] },
  { name: 'Kraken', domains: ['kraken.com'], keywords: ['kraken'] },
  { name: 'MetaMask', domains: ['metamask.io'], keywords: ['metamask'] },
  { name: 'Trust Wallet', domains: ['trustwallet.com'], keywords: ['trustwallet'] },
  { name: 'Ledger', domains: ['ledger.com', 'ledgerwallet.com'], keywords: ['ledgerwallet', 'ledger'] },
  { name: 'OpenSea', domains: ['opensea.io'], keywords: ['opensea'] },
  { name: 'KuCoin', domains: ['kucoin.com'], keywords: ['kucoin'] },
  { name: 'Bybit', domains: ['bybit.com'], keywords: ['bybit'] },
  { name: 'OKX', domains: ['okx.com'], keywords: ['okx'] },

  // E-Commerce & Shipping
  { name: 'eBay', domains: ['ebay.com', 'ebay.co.uk', 'ebay.de'], keywords: ['ebay'] },
  { name: 'Walmart', domains: ['walmart.com'], keywords: ['walmart'] },
  { name: 'Target', domains: ['target.com'], keywords: ['target'] },
  { name: 'Alibaba / AliExpress', domains: ['alibaba.com', 'aliexpress.com'], keywords: ['alibaba', 'aliexpress'] },
  { name: 'DHL', domains: ['dhl.com', 'dhl.de'], keywords: ['dhl', 'dhlexpress'] },
  { name: 'FedEx', domains: ['fedex.com'], keywords: ['fedex'] },
  { name: 'UPS', domains: ['ups.com'], keywords: ['ups'] },
  { name: 'USPS', domains: ['usps.com'], keywords: ['usps'] },
  { name: 'Royal Mail', domains: ['royalmail.com'], keywords: ['royalmail'] },
  { name: 'La Poste', domains: ['laposte.fr'], keywords: ['laposte'] },

  // Telecom & Identity
  { name: 'DocuSign', domains: ['docusign.com', 'docusign.net'], keywords: ['docusign'] },
  { name: 'Dropbox Sign / HelloSign', domains: ['hellosign.com'], keywords: ['hellosign'] },
  { name: 'AT&T', domains: ['att.com'], keywords: ['att'] },
  { name: 'Verizon', domains: ['verizon.com'], keywords: ['verizon'] },
  { name: 'T-Mobile', domains: ['t-mobile.com'], keywords: ['tmobile', 't-mobile'] },
  { name: 'Vodafone', domains: ['vodafone.com'], keywords: ['vodafone'] },
  { name: 'Orange', domains: ['orange.com', 'orange.fr'], keywords: ['orange'] }
];

const SUSPICIOUS_SUBDOMAIN_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'auth', 'authorize', 'authentication',
  'verify', 'verification', 'secure', 'security', 'account', 'accounts',
  'update', 'confirm', 'validation', 'validate', 'portal', 'wallet', 'connect',
  'recovery', 'support', 'helpdesk', 'claim', 'airdrop', 'reward', 'bonus',
  'billing', 'invoice', 'payment', 'banking', 'onlinebanking', 'service', 'client'
];

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { TOP_BRANDS, SUSPICIOUS_SUBDOMAIN_KEYWORDS };
}
