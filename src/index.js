const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=UTF-8" },
  });

const s = (v, n = 300) => String(v || "").trim().slice(0, n);

const FEE_RATE_BPS = {
  attended: 2000,
  unattended_card: 2500,
};

function makeId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function makeBookingCode() {
  const ymd = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `SB-${ymd}-${rand}`;
}

function makeReceiptNo() {
  const ymd = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `RCP-${ymd}-${rand}`;
}

function calcFeeJpy(amountJpy, rateBps) {
  return Math.floor((amountJpy * rateBps) / 10000);
}

function resolveReceiptPeriod(billingCycle, anchorDateStr) {
  const m = String(anchorDateStr || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const check = new Date(Date.UTC(year, month - 1, day));
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day
  ) {
    return null;
  }
  const mm = String(month).padStart(2, "0");
  const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const ddLast = String(lastDay).padStart(2, "0");

  if (billingCycle === "per_booking") {
    const dd = String(day).padStart(2, "0");
    const d = `${year}-${mm}-${dd}`;
    return { periodStartDate: d, periodEndDate: d };
  }
  if (billingCycle === "half_month") {
    if (day <= 15) {
      return { periodStartDate: `${year}-${mm}-01`, periodEndDate: `${year}-${mm}-15` };
    }
    return { periodStartDate: `${year}-${mm}-16`, periodEndDate: `${year}-${mm}-${ddLast}` };
  }
  if (billingCycle === "monthly") {
    return { periodStartDate: `${year}-${mm}-01`, periodEndDate: `${year}-${mm}-${ddLast}` };
  }
  return null;
}

function formatReceiptItemRow(row) {
  const baseAmount = Number(row.amount_jpy || 0);
  const code = row.booking_code || row.booking_id || "";
  if (row.tx_type === "prepay_fee") {
    return { signedAmountJpy: Math.abs(baseAmount), description: `予約先払い手数料（${code}）` };
  }
  if (row.tx_type === "penalty_capture") {
    return { signedAmountJpy: Math.abs(baseAmount), description: `キャンセル料・ペナルティ（${code}）` };
  }
  if (row.tx_type === "refund") {
    return { signedAmountJpy: -Math.abs(baseAmount), description: `返金調整（${code}）` };
  }
  return {
    signedAmountJpy: baseAmount,
    description: `利用明細（${row.tx_type || "payment"} / ${code}）`,
  };
}
