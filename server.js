const express = require("express");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 10000;
const CHARIOW_WEBHOOK_SECRET = process.env.CHARIOW_WEBHOOK_SECRET || "";

// IMPORTANT :
// express.raw() permet de conserver exactement le corps reçu.
// C'est nécessaire pour vérifier correctement une signature HMAC.
app.use(
  express.raw({
    type: "*/*",
    limit: "1mb"
  })
);

// ----------------------------------------------------
// Page de contrôle Render
// ----------------------------------------------------
app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    service: "DavKingBoost Chariow Webhook",
    status: "online"
  });
});

// ----------------------------------------------------
// Endpoint de contrôle
// ----------------------------------------------------
app.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    status: "healthy"
  });
});

// ----------------------------------------------------
// Fonctions utilitaires
// ----------------------------------------------------

function safeEqual(a, b) {
  try {
    const bufferA = Buffer.from(String(a));
    const bufferB = Buffer.from(String(b));

    if (bufferA.length !== bufferB.length) {
      return false;
    }

    return crypto.timingSafeEqual(bufferA, bufferB);
  } catch (error) {
    return false;
  }
}

function getSignature(req) {
  // On accepte plusieurs noms possibles afin d'éviter
  // de casser le webhook si le nom exact diffère.
  return (
    req.get("x-chariow-signature") ||
    req.get("chariow-signature") ||
    req.get("x-webhook-signature") ||
    req.get("webhook-signature") ||
    ""
  );
}

function verifySignature(rawBody, signature) {
  if (!CHARIOW_WEBHOOK_SECRET) {
    console.error("CHARIOW_WEBHOOK_SECRET absent.");
    return false;
  }

  if (!signature) {
    console.error("Signature Chariow absente.");
    return false;
  }

  // Signature HMAC SHA-256.
  const expectedHex = crypto
    .createHmac("sha256", CHARIOW_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex");

  const expectedBase64 = crypto
    .createHmac("sha256", CHARIOW_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("base64");

  // Quelques formats courants.
  const received = String(signature).trim();

  const candidates = [
    received,
    received.replace(/^sha256=/i, ""),
    received.replace(/^v1=/i, "")
  ];

  return candidates.some(
    candidate =>
      safeEqual(candidate, expectedHex) ||
      safeEqual(candidate, expectedBase64)
  );
}

// ----------------------------------------------------
// WEBHOOK CHARIOW
// ----------------------------------------------------

app.post("/webhook/chariow", async (req, res) => {
  try {
    const rawBody = req.body;

    if (!Buffer.isBuffer(rawBody) || rawBody.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Charge utile vide."
      });
    }

    const signature = getSignature(req);

    if (!verifySignature(rawBody, signature)) {
      console.error("Signature webhook invalide.");

      return res.status(401).json({
        success: false,
        message: "Signature invalide."
      });
    }

    let payload;

    try {
      payload = JSON.parse(rawBody.toString("utf8"));
    } catch (error) {
      return res.status(400).json({
        success: false,
        message: "JSON invalide."
      });
    }

    const event = payload.event || "";
    const sale = payload.sale || {};
    const saleId = sale.id || null;
    const status = sale.status || null;

    console.log("========== CHARIOW ==========");
    console.log("Event :", event);
    console.log("Sale ID :", saleId);
    console.log("Status :", status);
    console.log("=============================");

    // Nous ne déclenchons une commande que pour une vente réussie.
    if (event !== "successful.sale") {
      return res.status(200).json({
        success: true,
        received: true,
        ignored: true,
        event
      });
    }

    if (!saleId) {
      return res.status(400).json({
        success: false,
        message: "Identifiant de vente absent."
      });
    }

    // ------------------------------------------------
    // Référence DavKingBoost
    // ------------------------------------------------

    let davkiReference = null;

    if (Array.isArray(sale.custom_fields)) {
      const referenceField = sale.custom_fields.find(field => {
        const name = String(field.name || "")
          .trim()
          .toLowerCase();

        return (
          name === "reference_davki" ||
          name === "référence davki" ||
          name === "reference davki"
        );
      });

      if (referenceField) {
        davkiReference = referenceField.value || null;
      }
    }

    console.log("Référence DavKingBoost :", davkiReference);

    /*
     * IMPORTANT
     * --------------------------------------------------
     * À ce stade :
     *
     * 1. Chariow a confirmé successful.sale
     * 2. la signature a été vérifiée
     * 3. sale.id est disponible
     * 4. la référence DavKingBoost est récupérée
     *
     * La prochaine connexion sera :
     *
     * Render
     *   -> DavKingBoost / InfinityFree
     *   -> retrouver la commande par référence
     *   -> vérifier qu'elle n'a pas déjà été envoyée
     *   -> créer la commande SMMZIO
     *
     * On NE crée volontairement PAS encore la commande
     * SMMZIO ici tant que le format exact de orders.json
     * et de ton API DavKingBoost n'est pas raccordé.
     */

    return res.status(200).json({
      success: true,
      received: true,
      event,
      sale_id: saleId,
      reference: davkiReference
    });

  } catch (error) {
    console.error("Erreur webhook :", error);

    return res.status(500).json({
      success: false,
      message: "Erreur interne."
    });
  }
});

// ----------------------------------------------------
// 404
// ----------------------------------------------------

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route introuvable."
  });
});

// ----------------------------------------------------
// Démarrage Render
// ----------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
  console.log(`DavKingBoost webhook actif sur le port ${PORT}`);
});
