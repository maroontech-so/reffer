/**
 * palpluss.js — PalPluss payment provider
 * Handles both M-Pesa STK Push (collections) and B2C payouts (disbursements).
 *
 * Docs: https://docs.palpluss.com
 * Base URL: https://api.palpluss.com/v1
 * Auth: HTTP Basic — API key as username, empty password.
 */
"use strict";

const axios = require("axios");

const BASE_URL = process.env.PALPLUSS_BASE_URL || "https://api.palpluss.com/v1";

function basicAuthHeader() {
  const apiKey = process.env.PALPLUSS_API_KEY || "";
  if (!apiKey) {
    throw new Error("PalPluss is not configured: set PALPLUSS_API_KEY");
  }
  const token = Buffer.from(`${apiKey}:`).toString("base64");
  return `Basic ${token}`;
}

async function request(method, path, body, extraHeaders = {}) {
  const url = `${BASE_URL}${path}`;
  const headers = {
    Authorization: basicAuthHeader(),
    "Content-Type": "application/json",
    ...extraHeaders,
  };

  const res = await axios({
    method,
    url,
    headers,
    data: body,
    timeout: 25000,
    validateStatus: () => true,
  });

  const payload = res.data;
  if (!payload || typeof payload !== "object") {
    throw new Error(
      `PalPluss returned an invalid response (HTTP ${res.status})`,
    );
  }

  if (!payload.success) {
    const err = new Error(
      payload.error?.message || `PalPluss error (HTTP ${res.status})`,
    );
    err.code = payload.error?.code || "PALPLUSS_ERROR";
    err.httpStatus = res.status;
    err.requestId = payload.requestId;
    err.details = payload.error?.details;
    throw err;
  }

  return payload.data;
}

/**
 * Initiate an M-Pesa STK Push.
 * Endpoint: POST /payments/stk
 *
 * @param {Object} opts
 * @param {number} opts.amountKes        Amount in KES (e.g. 100)
 * @param {string} opts.phone            "254712345678" (no +)
 * @param {string} opts.callbackUrl      Publicly reachable HTTPS webhook URL
 * @param {string} opts.accountReference ≤ 12 characters, shown on M-Pesa statement
 * @param {string} [opts.description]    ≤ 13 characters, shown on PIN prompt
 * @param {string} [opts.channelId]      Optional PalPluss payment channel ID
 */
async function initiateStkPush({
  amountKes,
  phone,
  callbackUrl,
  accountReference,
  description,
  channelId,
}) {
  const body = {
    amount: Math.round(Number(amountKes)),
    phone,
    accountReference: String(accountReference || "").slice(0, 12),
    transactionDesc: String(description || "Payment").slice(0, 13),
    callbackUrl,
  };
  if (channelId) body.channelId = channelId;

  return request("POST", "/payments/stk", body);
}

/**
 * Initiate a B2C payout to an M-Pesa number.
 * Endpoint: POST /b2c/payouts
 *
 * @param {Object} opts
 * @param {number} opts.amountKes        Amount in KES (minimum KES 10)
 * @param {string} opts.phone            "254712345678"
 * @param {string} opts.reference        Your internal withdrawal reference
 * @param {string} [opts.description]    Human-readable description
 * @param {string} opts.callbackUrl      Webhook URL for B2C status
 * @param {string} [opts.idempotencyKey] Sent as Idempotency-Key header
 */
async function initiateB2CPayout({
  amountKes,
  phone,
  reference,
  description,
  callbackUrl,
  idempotencyKey,
}) {
  const body = {
    amount: Math.round(Number(amountKes)),
    phone,
    reference,
    description: description || "Commission payout",
    callbackUrl,
  };

  const headers = {};
  if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;

  return request("POST", "/b2c/payouts", body, headers);
}

/**
 * Fetch a PalPluss transaction by ID.
 * Endpoint: GET /transactions/{id}
 *
 * Normalises both camelCase and snake_case response fields so callers
 * can safely read .transactionFee / .mpesaReceipt / .resultDesc.
 */
async function getTransaction(transactionId) {
  const tx = await request(
    "GET",
    `/transactions/${encodeURIComponent(transactionId)}`,
  );

  return {
    ...tx,
    status: String(tx.status || "").toUpperCase(),
    amount: tx.amount,
    transactionFee: tx.transactionFee ?? tx.transaction_fee ?? 0,
    mpesaReceipt: tx.mpesaReceipt ?? tx.mpesa_receipt ?? null,
    resultDesc: tx.resultDesc ?? tx.result_desc ?? null,
    resultCode: tx.resultCode ?? tx.result_code ?? null,
  };
}

module.exports = {
  initiateStkPush,
  initiateB2CPayout,
  getTransaction,
};
