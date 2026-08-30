# 25 types of scams:
COERCION_PROTOTYPES = {

    "CREDENTIAL_PHISHING": [
        "The recipient is asked to provide their username and password.",
        "The recipient is directed to sign in through a provided link to verify their account.",
        "The recipient is asked to confirm or update their login credentials.",
        "The recipient is instructed to enter a password on a website to restore account access.",
        "The recipient is asked to provide a one-time password or authentication code.",
        "The message attempts to collect account credentials through a fake login page.",
        "The recipient is told that their credentials must be verified to prevent account suspension.",
        "The recipient is asked to disclose authentication information to resolve an account problem.",
    ],

    "ACCOUNT_TAKEOVER": [
        "The recipient is warned that someone has accessed their account without authorization.",
        "The message claims that suspicious login activity was detected on the account.",
        "The recipient is told that an unknown device or location accessed their account.",
        "The recipient is warned that their password or recovery information has been changed.",
        "The message claims that another person is currently using the recipient's account.",
        "The recipient is instructed to secure or recover an allegedly compromised account.",
        "The message claims that unauthorized actions or transactions were performed through the account.",
        "The recipient is told to regain control of an account that has supposedly been hijacked.",
    ],

    "PAYMENT_CARD_FRAUD": [
        "The recipient is asked to provide credit or debit card information.",
        "The message requests a card number, expiration date, or security code.",
        "The recipient is warned about suspicious card activity and asked to verify the card.",
        "The message claims that the payment card has been blocked and needs verification.",
        "The recipient is asked to update card details through a provided link.",
        "The message requests a CVV, PIN, or other card security information.",
        "The recipient is told that an unauthorized card transaction requires immediate action.",
        "The message uses a fake payment verification process to obtain card information.",
    ],

    "BUSINESS_EMAIL_COMPROMISE": [
        "The sender impersonates a company executive and requests an urgent money transfer.",
        "An employee is instructed to make a confidential payment on behalf of a manager.",
        "The sender pretends to be a supplier and asks for an invoice payment.",
        "The recipient is told to change the bank account used for an upcoming business payment.",
        "The message requests payment using altered or fraudulent banking details.",
        "The sender impersonates a trusted business contact to obtain sensitive company information.",
        "The recipient is pressured to bypass normal approval procedures for a financial transaction.",
        "The message attempts to redirect legitimate business funds to a fraudulent account.",
    ],

    "GOVERNMENT_IMPERSONATION": [
        "The sender falsely claims to represent a government agency.",
        "The recipient is threatened with legal consequences by someone impersonating a government official.",
        "The message claims that the recipient owes money to a government authority.",
        "The recipient is told that government benefits or services will be suspended unless they respond.",
        "The sender impersonates law enforcement and threatens arrest or prosecution.",
        "The message requests personal information while posing as an official government institution.",
        "The sender uses government authority or official-looking notices to pressure the recipient.",
    ],

    "DELIVERY_SCAM": [
        "The message claims that a package could not be delivered.",
        "The recipient is asked to pay a fee to receive or reschedule a delivery.",
        "The message asks the recipient to confirm or update their delivery address.",
        "The recipient is told that a parcel is being held because of an unpaid charge.",
        "The message contains a fake missed-delivery notification.",
        "The sender impersonates a courier or postal service.",
        "The recipient is told that the package will be returned unless immediate action is taken.",
        "The message provides a suspicious tracking link that supposedly contains delivery information.",
    ],

    "SUBSCRIPTION_SCAM": [
        "The recipient is told that an unexpected subscription charge will be made.",
        "The message claims that a subscription has been automatically renewed.",
        "The recipient is asked to cancel a subscription through a provided link or phone number.",
        "The message falsely claims that a membership has been renewed without authorization.",
        "The recipient is asked to provide payment information to stop a recurring charge.",
        "The message uses a fake subscription invoice to make the recipient contact support.",
        "The recipient is told that a premium service was activated and must be canceled.",
    ],

    "TECH_SUPPORT_SCAM": [
        "The recipient is falsely warned that their computer has a serious security problem.",
        "The message claims that malware or a virus was detected on the recipient's device.",
        "The recipient is instructed to contact technical support immediately.",
        "The sender impersonates a technology company or software provider.",
        "The recipient is asked to install software so a supposed technician can access the device.",
        "The message pressures the recipient to allow remote access to their computer.",
        "The recipient is asked to pay for unnecessary technical support or security services.",
        "The message uses a fake security alert to convince the recipient to call support.",
    ],

    "INVESTMENT_SCAM": [
        "The recipient is promised unusually high returns from an investment.",
        "The message claims that the investment carries little or no financial risk.",
        "The recipient is encouraged to invest money quickly before an opportunity expires.",
        "The sender claims that an investment will produce guaranteed or extremely high profits.",
        "The message offers exclusive access to a supposedly profitable investment opportunity.",
        "The sender claims to possess insider information about a profitable investment.",
        "The message uses fabricated success stories to convince the recipient to invest.",
    ],

    "CRYPTOCURRENCY_SCAM": [
        "The recipient is promised guaranteed profits from a cryptocurrency investment.",
        "The recipient is asked to send cryptocurrency to an unknown wallet.",
        "The message claims that a cryptocurrency giveaway requires an initial payment.",
        "The recipient is directed to a fake cryptocurrency investment or trading platform.",
        "The message asks for a wallet recovery phrase or cryptocurrency account credentials.",
        "The recipient is asked to pay a cryptocurrency fee to unlock or withdraw funds.",
        "The sender impersonates a cryptocurrency exchange to obtain account access or funds.",
        "The message promises rapid profits from buying or trading a cryptocurrency.",
    ],

    "JOB_RECRUITMENT_SCAM": [
        "The recipient is offered a job that requires an upfront payment.",
        "The message promises unusually high pay for simple or inexperienced work.",
        "The recipient is asked to pay for training, equipment, registration, or processing.",
        "The sender offers employment without a normal interview or hiring process.",
        "The recipient is asked to provide personal or banking information for a suspicious job.",
        "The message claims that the recipient was selected for a job they never applied for.",
        "The sender asks the recipient to transfer money or purchase items as part of a job.",
        "The message uses a fake recruitment process to obtain money or personal information.",
    ],

    "LOAN_CREDIT_SCAM": [
        "The recipient is guaranteed approval for a loan regardless of their credit history.",
        "The message offers a loan without a credit check or normal verification.",
        "The recipient is asked to pay an upfront fee before receiving the loan.",
        "The sender promises instant credit approval in exchange for a processing payment.",
        "The message claims that a loan has been approved even though the recipient never applied.",
        "The recipient is asked to provide banking or personal information to receive the loan.",
        "The sender requests payment for insurance, taxes, or processing before releasing loan funds.",
    ],

    "LOTTERY_PRIZE_SCAM": [
        "The recipient is told that they have won a lottery or prize.",
        "The message claims that the recipient won money despite never entering a competition.",
        "The recipient is asked to pay a fee or tax before receiving the prize.",
        "The sender claims that a large cash reward is waiting to be collected.",
        "The recipient is asked to provide personal or banking information to claim winnings.",
        "The message pressures the recipient to act quickly before the prize expires.",
        "The sender claims that a processing fee is required to release the prize.",
    ],

    "REFUND_SCAM": [
        "The recipient is told that they are entitled to an unexpected refund.",
        "The message claims that a billing error resulted in money being owed to the recipient.",
        "The recipient is asked to provide banking information to receive a refund.",
        "The sender claims that a refund is pending and requires verification.",
        "The recipient is directed to a link to claim a supposed refund.",
        "The sender impersonates a company to process a fraudulent refund.",
        "The message uses a fake refund notification to obtain financial or personal information.",
    ],

    "SHOPPING_ECOMMERCE_SCAM": [
        "The message advertises products at prices that are unusually low.",
        "The recipient is directed to a suspicious online store offering large discounts.",
        "The seller requests payment for goods that may never be delivered.",
        "The message promotes a fake online store impersonating a legitimate retailer.",
        "The seller asks for payment through an unusual or insecure method.",
        "The recipient is pressured to buy immediately because of a supposed limited-time sale.",
        "The message advertises counterfeit, nonexistent, or misleading products.",
        "The recipient is directed to enter payment information on a suspicious shopping website.",
    ],

    "MALWARE_DELIVERY": [
        "The recipient is encouraged to download a suspicious attachment.",
        "The message contains a malicious file disguised as a legitimate document.",
        "The recipient is directed to download software from an untrusted link.",
        "The sender asks the recipient to open an attachment containing potentially harmful code.",
        "The recipient is instructed to enable macros or other active content in a document.",
        "The message disguises an executable file as an invoice, report, or other document.",
        "The recipient is tricked into installing a fake software update or application.",
        "The message uses an attachment or download to deliver malware.",
    ],

    "IDENTITY_INFORMATION_THEFT": [
        "The recipient is asked to provide sensitive personal identification information.",
        "The message requests a national ID number, tax ID, or similar identifying information.",
        "The recipient is asked to submit a passport or identity card.",
        "The sender requests personal details that could be used to impersonate the recipient.",
        "The recipient is instructed to provide identity information for suspicious verification.",
        "The message attempts to collect enough personal information to commit identity fraud.",
        "The recipient is asked to disclose private identifying information for an unverified purpose.",
    ],

    "EXTORTION_BLACKMAIL": [
        "The sender threatens the recipient and demands money to prevent harm.",
        "The message claims to possess embarrassing or private information about the recipient.",
        "The recipient is threatened with exposure unless a payment is made.",
        "The sender claims to have compromising photos, videos, or personal data.",
        "The message demands cryptocurrency in exchange for keeping information private.",
        "The sender threatens to publish damaging information unless the recipient complies.",
        "The message claims that the recipient's device or account was hacked and demands a ransom.",
        "The recipient is pressured to pay money in exchange for silence or to prevent disclosure.",
    ],

    "ROMANCE_RELATIONSHIP_SCAM": [
        "The sender develops a romantic relationship online before asking for money.",
        "The sender quickly expresses strong romantic feelings to gain the recipient's trust.",
        "The supposed romantic partner asks for financial help because of an emergency.",
        "The sender repeatedly gives excuses for being unable to meet in person.",
        "The recipient is asked to send money for travel, medical expenses, or another personal crisis.",
        "The sender uses emotional attachment and affection to persuade the recipient to provide financial support.",
        "The romantic relationship is used as a means to obtain money, gifts, or other financial assistance.",
    ],

    "CHARITY_SCAM": [
        "The recipient is asked to donate money to a charity or relief organization that may be fraudulent.",
        "The sender impersonates a legitimate charity to collect donations.",
        "The message requests urgent donations for people affected by a disaster or crisis.",
        "The sender uses an emotional humanitarian appeal to persuade the recipient to send money.",
        "The recipient is asked to donate through an unusual or unverified payment method.",
        "The message uses a fake charitable cause to obtain money or financial information.",
    ],

    "INVOICE_PAYMENT_DIVERSION_SCAM": [
        "The sender asks the recipient to send a business payment to a new bank account.",
        "The message claims that a supplier's banking details have changed.",
        "The recipient is instructed to redirect an invoice payment to another account.",
        "The sender impersonates a vendor and provides fraudulent payment instructions.",
        "The recipient receives an invoice containing altered bank account information.",
        "The message requests an urgent change to the payment destination.",
        "The sender attempts to redirect a legitimate business payment to a fraudulent account.",
    ],

    "TAX_SCAM": [
        "The message falsely claims that the recipient owes unpaid taxes.",
        "The recipient is threatened with penalties or legal action for an alleged tax debt.",
        "The sender impersonates a tax authority and demands immediate payment.",
        "The message claims that the recipient is entitled to a tax refund and requests personal information.",
        "The recipient is asked to pay supposed taxes through an unusual payment method.",
        "The message claims that an urgent tax return or filing problem must be resolved.",
        "The sender uses the authority of a tax agency to frighten the recipient into sending money or information.",
    ],

    "IMMIGRATION_VISA_SCAM": [
        "The message claims that there is a problem with the recipient's visa or immigration status.",
        "The recipient is promised guaranteed visa approval in exchange for payment.",
        "The sender impersonates an immigration authority and requests personal information.",
        "The message offers fast-track visa or immigration services for an upfront fee.",
        "The recipient is threatened with deportation or legal consequences over an alleged immigration issue.",
        "The recipient is asked to provide passport or immigration documents for suspicious verification.",
        "The message demands payment to process, renew, or release a visa or permit.",
    ],

    "UTILITY_SERVICE_DISCONNECTION_SCAM": [
        "The recipient is warned that their electricity service will be disconnected.",
        "The message claims that an unpaid utility bill requires immediate payment.",
        "The recipient is threatened with termination of water, gas, electricity, or internet service.",
        "The sender impersonates a utility company and demands urgent payment.",
        "The recipient is told that service will be disconnected unless payment is made immediately.",
        "The message asks the recipient to use an unusual payment method to restore service.",
        "The recipient is directed to a suspicious payment link to prevent service disconnection.",
    ],

    "FAKE_MARKETPLACE_P2P_SCAM": [
        "The buyer or seller asks the recipient to make payment outside the official marketplace.",
        "The sender provides a fake payment confirmation showing that money was supposedly sent.",
        "The recipient is asked to pay an additional fee before receiving marketplace funds.",
        "The message claims that a payment is pending and requires an account upgrade.",
        "The sender asks the recipient to refund an alleged accidental overpayment.",
        "The buyer uses a fake transaction receipt to persuade the seller to release the item.",
        "The recipient is directed to a fake payment page to receive money from a buyer.",
        "The message uses a fraudulent marketplace payment notification to obtain money or goods.",
    ],

    "BENIGN" : [
        "Thank you for your email and I will get back to you soon.",
        "The meeting has been scheduled for tomorrow at 10 AM.",
        "Please find the attached report for your review.",
        "I hope you are doing well.",
        "The project deadline has been extended until Friday.",
        "Let us know if you have any questions.",
        "Your order has been successfully delivered.",
        "Your account statement is now available.",
        "The weather is expected to be pleasant this weekend.",
        "I have completed the requested task."
    ]
}

URGENCY_PATTERNS_REGEX = [

    # direct urgency
    r"\burgent\b",
    r"\burgently\b",
    r"\bimmediately\b",
    r"\basap\b",
    r"\bright\s+away\b",
    r"\bat\s+once\b",
    r"\bwithout\s+delay\b",
    r"\bact\s+now\b",
    r"\bdo\s+not\s+delay\b",
    r"\bpromptly\b",

    # explicit short deadlines
    r"\bwithin\s+\d+\s*(?:minutes?|hours?|days?)\b",
    r"\bwithin\s+(?:one|an?)\s*(?:minute|hour|day)\b",
    r"\b(?:in|within)\s+the\s+next\s+\d+\s*(?:minutes?|hours?|days?)\b",

    # temporal deadlines
    r"\bbefore\s+(?:the\s+)?(?:end\s+of\s+the\s+day|deadline)\b",
    r"\bby\s+(?:the\s+)?end\s+of\s+(?:today|the\s+day)\b",
    r"\btoday\b",
    r"\bthis\s+(?:morning|afternoon|evening)\b",
    r"\bby\s+\d{1,2}(?::\d{2})?\s*(?:am|pm)?\b",
    r"\bby\s+(?:today|tomorrow|tonight)\b",

    # explicit expiration / cutoff language
    r"\bbefore\s+(?:it\s+)?expires?\b",
    r"\bexpires?\s+(?:today|tomorrow|soon|within)\b",
    r"\bdeadline\b",
    r"\b(?:final|last)\s+(?:notice|warning|reminder)\b",
]

URGENCY_PATTERNS_SEMANTIC = [

    # pressure to act quickly
    "The recipient is pressured to take action quickly.",
    "The recipient is expected to take action without delay.",
    "The message creates pressure to act immediately.",
    "The sender emphasizes that the recipient must act quickly.",

    # consequences for waiting
    "The recipient is warned that delaying action may cause a problem.",
    "The message implies that waiting could result in negative consequences.",
    "The recipient is pressured by a threat of losing access or facing consequences.",
    "The message creates a sense that there is very little time to respond.",

    # deadline / limited time
    "The recipient is given a strict deadline for completing an action.",
    "The recipient is told that an action must be completed before a deadline.",
    "The message indicates that an opportunity or access may expire soon.",
    "The recipient is told that action must be completed within a limited period.",

    # escalation / final warning
    "The message presents the request as a final warning requiring immediate attention.",
    "The sender suggests that this is the last opportunity to take action.",
    "The recipient is warned that failure to respond promptly will trigger consequences.",

    # overall coercive urgency
    "The message uses time pressure to force the recipient to comply.",
    "The message attempts to rush the recipient into making a decision.",
    "The recipient is made to feel that immediate compliance is necessary.",
]


intent_risk = {

    # Credential and identity attacks
    "CREDENTIAL_PHISHING": 0.90,
    "ACCOUNT_TAKEOVER": 0.95,
    "IDENTITY_INFORMATION_THEFT": 0.95,

    # Financial fraud
    "PAYMENT_CARD_FRAUD": 0.90,
    "BUSINESS_EMAIL_COMPROMISE": 0.95,
    "INVOICE_PAYMENT_DIVERSION_SCAM": 0.95,
    "LOAN_CREDIT_SCAM": 0.75,
    "INVESTMENT_SCAM": 0.85,
    "CRYPTOCURRENCY_SCAM": 0.85,

    # Impersonation scams
    "GOVERNMENT_IMPERSONATION": 0.85,
    "TAX_SCAM": 0.90,
    "IMMIGRATION_VISA_SCAM": 0.85,
    "UTILITY_SERVICE_DISCONNECTION_SCAM": 0.80,

    # Delivery and service scams
    "DELIVERY_SCAM": 0.65,
    "SUBSCRIPTION_SCAM": 0.65,
    "TECH_SUPPORT_SCAM": 0.85,
    "REFUND_SCAM": 0.75,

    # Malware and direct compromise
    "MALWARE_DELIVERY": 0.95,

    # Recruitment and prize scams
    "JOB_RECRUITMENT_SCAM": 0.70,
    "LOTTERY_PRIZE_SCAM": 0.70,

    # Commerce scams
    "SHOPPING_ECOMMERCE_SCAM": 0.65,
    "FAKE_MARKETPLACE_P2P_SCAM": 0.75,

    # Social engineering scams
    "EXTORTION_BLACKMAIL": 0.95,
    "ROMANCE_RELATIONSHIP_SCAM": 0.70,
    "CHARITY_SCAM": 0.60,
}
