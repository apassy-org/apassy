// The facts of the legal pages that only the owner can give (implementation plan
// s7, owner-needed step 3). Each `null` renders as the marker below. A legal page
// that is not a draft fails the build while it shows the marker
// (layouts/Legal.astro), so a placeholder cannot go live.

export const OWNER_TEXT_NEEDED = "OWNER-TEXT-NEEDED";

export const LEGAL: Record<string, string | null> = {
  /** The legal name of the seller: a company, or a person with a trading name. */
  legalName: "Productmesh Rafał Wyderka",
  /** The legal form and the register entry, for example the KRS or CEIDG number. */
  register: "Sole proprietorship (jednoosobowa działalność gospodarcza), entered in CEIDG, the Polish business register",
  /** The postal address of the seller. */
  address: "ul. Mokra 33, 03-562 Warszawa, Poland",
  /** The EU VAT id (NIP with the prefix PL). */
  vatId: "PL5242920020",
  /** The e-mail address for contracts, withdrawal, refunds, and privacy requests. */
  email: "apassy@wyderka.cc",
  /** The law that governs the contract, for example "the law of Poland". */
  governingLaw: "the law of Poland",
  /** The courts for disputes with business customers. */
  courts: "Warsaw, Poland",
  /** The date the terms come into force. */
  effectiveDate: "21 November 2026",
  /** The provider and the country of the server that runs Connect (today the VPS of the relay). */
  hosting: "Contabo GmbH (Germany), in the European Union",
  /** How long the hosted bouncer brain keeps a question and its answer (ADR 0035). */
  brainRetention: "Not offered yet: nothing is stored",
  /** The person responsible for the content of the site, if the imprint names one. */
  responsible: "Rafał Wyderka",
};
