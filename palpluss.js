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

// ---- Retryable B2C error classifier -------------------------------------
// These errors mean "B2C wallet has no float" — the payout will succeed
// after the admin tops up. Everything else (invalid phone, KYC missing,
// channel not configured) is terminal and must NOT be queued.
const RETRYABLE_B2C_CODES = new Set([
  "INSUFFICIENT_FUNDS",
  "WALLET_INACTIVE",
  "BALANCE_INSUFFICIENT",
]);

function isRetryableB2CError(err) {
  return Boolean(err && err.code && RETRYABLE_B2C_CODES.has(err.code));
}

module.exports = {
  initiateStkPush,
  initiateB2CPayout,
  getTransaction,
  isRetryableB2CError,
};
