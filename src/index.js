const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });

const s = (v, n = 300) => String(v || "").trim().slice(0, n);

async function importAesKey(base64Key) {
  const raw = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));
  if (raw.byteLength !== 32) {
    throw new Error("EKYC_ENCRYPTION_KEY must be 32 bytes (256-bit) in Base64");
  }
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptBytes(key, plainBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plainBytes
  );
  const ivBase64 = btoa(String.fromCharCode(...iv));
  return { cipherBuffer, ivBase64 };
}

async function decryptBytes(key, cipherBuffer, ivBase64) {
  const iv = Uint8Array.from(atob(ivBase64), (c) => c.charCodeAt(0));
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    cipherBuffer
  );
}
const FEE_RATE_BPS = {
  attended: 2000,        // 在室あり: 20%
  unattended_card: 2500, // 不在 / クレジット決済: 25%
};

function makeId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function makeBookingCode() {
  const now = new Date();
  const ymd = now.toISOString().slice(0, 10).replace(/-/g, '');
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `SB-${ymd}-${rand}`;
}

function calcFeeJpy(amountJpy, rateBps) {
  return Math.floor((amountJpy * rateBps) / 10000);
}
function makeReceiptNo() {
  const now = new Date();
  const ymd = now.toISOString().slice(0, 10).replace(/-/g, "");
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `RCP-${ymd}-${rand}`;
}

// 基準日（YYYY-MM-DD）から対象期間の開始日・終了日を算出
function resolveReceiptPeriod(billingCycle, anchorDateStr) {
  const m = String(anchorDateStr || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return null;

  const year = Number(m[1]);
  const month = Number(m[2]); // 1-12
  const day = Number(m[3]);   // 1-31

  const checkDate = new Date(Date.UTC(year, month - 1, day));
  if (
    checkDate.getUTCFullYear() !== year ||
    checkDate.getUTCMonth() !== month - 1 ||
    checkDate.getUTCDate() !== day
  ) {
    return null;
  }

  const mm = String(month).padStart(2, "0");
  const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const ddLast = String(lastDay).padStart(2, "0");

  if (billingCycle === "per_booking") {
    const dd = String(day).padStart(2, "0");
    const dateStr = `${year}-${mm}-${dd}`;
    return { periodStartDate: dateStr, periodEndDate: dateStr };
  }

  if (billingCycle === "half_month") {
    if (day <= 15) {
      return {
        periodStartDate: `${year}-${mm}-01`,
        periodEndDate: `${year}-${mm}-15`,
      };
    }
    return {
      periodStartDate: `${year}-${mm}-16`,
      periodEndDate: `${year}-${mm}-${ddLast}`,
    };
  }

  if (billingCycle === "monthly") {
    return {
      periodStartDate: `${year}-${mm}-01`,
      periodEndDate: `${year}-${mm}-${ddLast}`,
    };
  }

  return null;
}

// 決済種別に応じた明細文言と符号（返金はマイナス）
function formatReceiptItemRow(row) {
  const baseAmount = Number(row.amount_jpy || 0);
  const code = row.booking_code || row.booking_id || "";

  if (row.tx_type === "prepay_fee") {
    return {
      signedAmountJpy: Math.abs(baseAmount),
      description: `予約先払い手数料（${code}）`,
    };
  }
  if (row.tx_type === "penalty_capture") {
    return {
      signedAmountJpy: Math.abs(baseAmount),
      description: `キャンセル料・ペナルティ（${code}）`,
    };
  }
  if (row.tx_type === "refund") {
    return {
      signedAmountJpy: -Math.abs(baseAmount),
      description: `返金調整（${code}）`,
    };
  }
  return {
    signedAmountJpy: baseAmount,
    description: `利用明細（${row.tx_type || "payment"} / ${code}）`,
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 既存：サロン掲載用 画像アップロード
    if (url.pathname === "/api/upload" && request.method === "POST") {
      try {
        const form = await request.formData();
        const file = form.get("file");
        const salon = String(form.get("salon_id") || "");
        if (!file || typeof file === "string")
          return json({ ok: false, error: "ファイルがありません" }, 400);
        if (!file.type.startsWith("image/"))
          return json({ ok: false, error: "画像を選んでください" }, 400);
        if (file.size > 10 * 1024 * 1024)
          return json({ ok: false, error: "10MB以下の画像にしてください" }, 400);
        const ext = (file.type.split("/")[1] || "jpg").replace(/[^a-z0-9]/gi, "");
        const key = `owners/${Date.now()}-${crypto.randomUUID()}.${ext}`;
        await env.IMAGES_BUCKET.put(key, file.stream(), {
          httpMetadata: { contentType: file.type },
          customMetadata: { salon: encodeURIComponent(salon).slice(0, 200) },
        });
        return json({ ok: true, key });
      } catch (e) {
        return json({ ok: false, error: "保存に失敗しました" }, 500);
      }
    }
      // 1. 予約作成（手数料先払い待ち: pending_payment）
      if (request.method === "POST" && url.pathname === "/api/bookings") {
        const body = await request.json();
        const {
          space_id,
          guest_user_id,
          start_at,
          end_at,
          fee_mode,
          prepay_room = false,
          payment_due_minutes = 15,
        } = body;

        if (!space_id || !guest_user_id || !start_at || !end_at || !FEE_RATE_BPS[fee_mode]) {
          return json({ ok: false, error: "必須項目または fee_mode が不正です" }, 400);
        }

        const startMs = Date.parse(start_at);
        const endMs = Date.parse(end_at);
        if (Number.isNaN(startMs) || Number.isNaN(endMs) || endMs <= startMs) {
          return json({ ok: false, error: "start_at / end_at の日時が不正です" }, 400);
        }

        const space = await env.DB.prepare(
          `SELECT id, salon_id, title, base_price_jpy, is_active
           FROM salon_spaces WHERE id = ?`
        ).bind(space_id).first();

        if (!space || Number(space.is_active) !== 1) {
          return json({ ok: false, error: "利用可能な枠が見つかりません" }, 404);
        }

        const salon = await env.DB.prepare(
          `SELECT id, owner_user_id FROM salons WHERE id = ?`
        ).bind(space.salon_id).first();

        const nowIso = new Date().toISOString();
        const conflict = await env.DB.prepare(
          `SELECT id FROM bookings
           WHERE space_id = ?
             AND (
               status IN ('confirmed', 'completed')
               OR (status = 'pending_payment' AND (payment_due_at IS NULL OR payment_due_at > ?))
             )
             AND NOT (end_at <= ? OR start_at >= ?)
           LIMIT 1`
        ).bind(space_id, nowIso, start_at, end_at).first();

        if (conflict) {
          return json({ ok: false, error: "指定の時間帯はすでに予約または仮押さえされています" }, 409);
        }

        const feeRateBps = FEE_RATE_BPS[fee_mode];
        const roomAmountJpy = Number(space.base_price_jpy);
        const platformFeeJpy = calcFeeJpy(roomAmountJpy, feeRateBps);
        const totalPrepaidJpy = prepay_room ? roomAmountJpy + platformFeeJpy : platformFeeJpy;

        const bookingId = makeId("bkg");
        const bookingCode = makeBookingCode();
        const paymentDueAt = new Date(Date.now() + Number(payment_due_minutes) * 60 * 1000).toISOString();

        await env.DB.prepare(
          `INSERT INTO bookings (
            id, booking_code, space_id, salon_id, guest_user_id, host_user_id,
            start_at, end_at, fee_mode, fee_rate_bps,
            room_amount_jpy, platform_fee_jpy, total_prepaid_jpy,
            status, fee_payment_status, payment_due_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_payment', 'unpaid', ?)`
        ).bind(
          bookingId,
          bookingCode,
          space_id,
          space.salon_id,
          guest_user_id,
          salon?.owner_user_id ?? null,
          start_at,
          end_at,
          fee_mode,
          feeRateBps,
          roomAmountJpy,
          platformFeeJpy,
          totalPrepaidJpy,
          paymentDueAt
        ).run();

        return json({
          ok: true,
          booking_id: bookingId,
          booking_code: bookingCode,
          status: "pending_payment",
          fee_payment_status: "unpaid",
          fee_mode,
          fee_rate_percent: feeRateBps / 100,
          room_amount_jpy: roomAmountJpy,
          platform_fee_jpy: platformFeeJpy,
          total_prepaid_jpy: totalPrepaidJpy,
          payment_due_at: paymentDueAt,
        }, 201);
      }

      // 2. 手数料先払い完了 → 予約確定（confirmed）
      const payMatch = url.pathname.match(/^\/api\/bookings\/([^/]+)\/pay-fee$/);
      if (request.method === "POST" && payMatch) {
        const bookingId = payMatch[1];
        const body = await request.json().catch(() => ({}));
        const provider = body.provider || "manual_or_gateway";
        const providerTxId = body.provider_tx_id || null;

        const booking = await env.DB.prepare(
          `SELECT * FROM bookings WHERE id = ?`
        ).bind(bookingId).first();

        if (!booking) {
          return json({ ok: false, error: "予約が見つかりません" }, 404);
        }

        if (booking.status === "confirmed" && booking.fee_payment_status === "paid") {
          return json({ ok: true, message: "すでに先払い完了・確定済みです", booking_id: bookingId });
        }

        if (booking.status !== "pending_payment") {
          return json({ ok: false, error: `現在のステータス（${booking.status}）では先払い確定できません` }, 409);
        }

        const now = new Date();
        if (booking.payment_due_at && Date.parse(booking.payment_due_at) < now.getTime()) {
          return json({ ok: false, error: "先払い期限を過ぎています。予約をやり直してください" }, 410);
        }

        const nowIso = now.toISOString();
        const updated = await env.DB.prepare(
          `UPDATE bookings
           SET status = 'confirmed',
               fee_payment_status = 'paid',
               paid_at = ?,
               updated_at = ?
           WHERE id = ? AND status = 'pending_payment'`
        ).bind(nowIso, nowIso, bookingId).run();

        if (!updated.meta?.changes) {
          return json({ ok: false, error: "予約状態が変更されたため確定できませんでした" }, 409);
        }

        const paymentId = makeId("pay");
        await env.DB.prepare(
          `INSERT INTO booking_payments (
            id, booking_id, tx_type, amount_jpy, provider, provider_tx_id, status
          ) VALUES (?, ?, 'prepay_fee', ?, ?, ?, 'succeeded')`
        ).bind(
          paymentId,
          bookingId,
          Number(booking.total_prepaid_jpy),
          provider,
          providerTxId
        ).run();

        return json({
          ok: true,
          booking_id: bookingId,
          booking_code: booking.booking_code,
          status: "confirmed",
          fee_payment_status: "paid",
          paid_amount_jpy: Number(booking.total_prepaid_jpy),
          payment_id: paymentId,
          paid_at: nowIso,
        });
      }

      // 3. キャンセル制御
      const cancelMatch = url.pathname.match(/^\/api\/bookings\/([^/]+)\/cancel$/);
      if (request.method === "POST" && cancelMatch) {
        const bookingId = cancelMatch[1];
        const body = await request.json().catch(() => ({}));
        const actorUserId = body.actor_user_id || null;
        const actorRole = ["guest", "host", "admin", "system"].includes(body.actor_role)
          ? body.actor_role
          : "guest";
        const reason = body.reason || "";

        const booking = await env.DB.prepare(
          `SELECT b.*, s.free_cancel_before_minutes, s.late_cancel_penalty_bps, s.noshow_penalty_bps
           FROM bookings b
           JOIN salon_spaces s ON s.id = b.space_id
           WHERE b.id = ?`
        ).bind(bookingId).first();

        if (!booking) {
          return json({ ok: false, error: "予約が見つかりません" }, 404);
        }

        if (!["pending_payment", "confirmed"].includes(booking.status)) {
          return json({ ok: false, error: `現在のステータス（${booking.status}）はキャンセルできません` }, 409);
        }

        const now = new Date();
        const nowIso = now.toISOString();
        const minutesBeforeStart = Math.floor((Date.parse(booking.start_at) - now.getTime()) / 60000);
        const freeBeforeMin = Number(booking.free_cancel_before_minutes ?? 1440);
        const latePenaltyBps = Number(booking.late_cancel_penalty_bps ?? 5000);
        const noshowPenaltyBps = Number(booking.noshow_penalty_bps ?? 10000);

        const prepaidAmount = Number(booking.total_prepaid_jpy || 0);
        const isPaid = booking.fee_payment_status === "paid" && prepaidAmount > 0;

        let refundAmount = 0;
        let penaltyAmount = 0;
        let nextFeePaymentStatus = booking.fee_payment_status;
        let policyApplied = "unpaid_cancel";

        if (!isPaid) {
          refundAmount = 0;
          penaltyAmount = 0;
          nextFeePaymentStatus = "unpaid";
          policyApplied = "unpaid_pending_cancel";
        } else if (actorRole === "host" || actorRole === "admin") {
          refundAmount = prepaidAmount;
          penaltyAmount = 0;
          nextFeePaymentStatus = "refunded";
          policyApplied = "host_or_admin_full_refund";
        } else if (minutesBeforeStart >= freeBeforeMin) {
          refundAmount = prepaidAmount;
          penaltyAmount = 0;
          nextFeePaymentStatus = "refunded";
          policyApplied = "within_free_cancel_window";
        } else if (minutesBeforeStart > 0) {
          penaltyAmount = Math.min(prepaidAmount, calcFeeJpy(prepaidAmount, latePenaltyBps));
          refundAmount = Math.max(0, prepaidAmount - penaltyAmount);
          nextFeePaymentStatus = refundAmount === 0 ? "forfeited" : "partially_refunded";
          policyApplied = "late_cancel_penalty";
        } else {
          penaltyAmount = Math.min(prepaidAmount, calcFeeJpy(prepaidAmount, noshowPenaltyBps));
          refundAmount = Math.max(0, prepaidAmount - penaltyAmount);
          nextFeePaymentStatus = refundAmount === 0 ? "forfeited" : "partially_refunded";
          policyApplied = "past_start_time_penalty";
        }

        const updated = await env.DB.prepare(
          `UPDATE bookings
           SET status = 'cancelled',
               fee_payment_status = ?,
               cancelled_at = ?,
               cancelled_by_role = ?,
               cancel_reason = ?,
               refund_amount_jpy = ?,
               penalty_amount_jpy = ?,
               updated_at = ?
           WHERE id = ? AND status IN ('pending_payment', 'confirmed')`
        ).bind(
          nextFeePaymentStatus,
          nowIso,
          actorRole,
          reason,
          refundAmount,
          penaltyAmount,
          nowIso,
          bookingId
        ).run();

        if (!updated.meta?.changes) {
          return json({ ok: false, error: "キャンセル処理が競合しました" }, 409);
        }

        const logId = makeId("clog");
        await env.DB.prepare(
          `INSERT INTO booking_cancel_logs (
            id, booking_id, actor_user_id, actor_role, minutes_before_start,
            policy_applied, calculated_refund_jpy, calculated_penalty_jpy, note
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          logId,
          bookingId,
          actorUserId,
          actorRole,
          minutesBeforeStart,
          policyApplied,
          refundAmount,
          penaltyAmount,
          reason
        ).run();

        if (refundAmount > 0) {
          await env.DB.prepare(
            `INSERT INTO booking_payments (
              id, booking_id, tx_type, amount_jpy, provider, status
            ) VALUES (?, ?, 'refund', ?, 'manual_or_gateway', 'succeeded')`
          ).bind(makeId("pay"), bookingId, refundAmount).run();
        }

        if (penaltyAmount > 0) {
          await env.DB.prepare(
            `INSERT INTO booking_payments (
              id, booking_id, tx_type, amount_jpy, provider, status
            ) VALUES (?, ?, 'penalty_capture', ?, 'manual_or_gateway', 'succeeded')`
          ).bind(makeId("pay"), bookingId, penaltyAmount).run();
        }

        return json({
          ok: true,
          booking_id: bookingId,
          status: "cancelled",
          fee_payment_status: nextFeePaymentStatus,
          minutes_before_start: minutesBeforeStart,
          policy_applied: policyApplied,
                 refund_amount_jpy: refundAmount,
       penalty_amount_jpy: penaltyAmount,
       cancel_log_id: logId,
     });
   }

     // 4. オンライン領収書の発行（都度 per_booking / 半月 half_month / 毎月 monthly）

        // 4. オンライン領収書の発行（都度 per_booking / 半月 half_month / 毎月 monthly）
      if (request.method === "POST" && url.pathname === "/api/receipts/issue") {
        const body = await request.json();
        const {
          target_user_id,
          target_role = "guest",
          billing_cycle,
          booking_id = null,
          anchor_date = null,
          recipient_name = "",
          issuer_name = "salon-base",
        } = body;

        if (
          !target_user_id ||
          !["guest", "host"].includes(target_role) ||
          !["per_booking", "half_month", "monthly"].includes(billing_cycle)
        ) {
          return json({ ok: false, error: "必須項目またはパラメータが不正です" }, 400);
        }

        const user = await env.DB.prepare(
          `SELECT id, name, email FROM users WHERE id = ?`
        ).bind(target_user_id).first();

        if (!user) {
          return json({ ok: false, error: "対象ユーザーが見つかりません" }, 404);
        }

        let effectiveAnchorDate = anchor_date;
        let targetBooking = null;

        if (billing_cycle === "per_booking") {
          if (!booking_id) {
            return json({ ok: false, error: "都度発行（per_booking）には booking_id が必要です" }, 400);
          }
          targetBooking = await env.DB.prepare(
            `SELECT * FROM bookings WHERE id = ?`
          ).bind(booking_id).first();

          if (!targetBooking) {
            return json({ ok: false, error: "対象予約が見つかりません" }, 404);
          }

          const baseIso = targetBooking.paid_at || targetBooking.start_at || targetBooking.created_at;
          effectiveAnchorDate = effectiveAnchorDate || String(baseIso).slice(0, 10);
        } else {
          effectiveAnchorDate = effectiveAnchorDate || new Date().toISOString().slice(0, 10);
        }

        const period = resolveReceiptPeriod(billing_cycle, effectiveAnchorDate);
        if (!period) {
          return json({ ok: false, error: "対象期間の日付（YYYY-MM-DD）が不正です" }, 400);
        }

        const { periodStartDate, periodEndDate } = period;

        // すでに発行済みの領収書があれば重複作成せず返す
        const existing = await env.DB.prepare(
          `SELECT * FROM receipts
           WHERE target_user_id = ?
             AND target_role = ?
             AND billing_cycle = ?
             AND period_start_date = ?
             AND period_end_date = ?
             AND status = 'issued'
           ORDER BY created_at DESC
           LIMIT 1`
        ).bind(
          target_user_id,
          target_role,
          billing_cycle,
          periodStartDate,
          periodEndDate
        ).first();

        if (existing) {
          const existingItems = await env.DB.prepare(
            `SELECT id, booking_id, booking_payment_id, description, amount_jpy, sort_order
             FROM receipt_items
             WHERE receipt_id = ?
             ORDER BY sort_order ASC`
          ).bind(existing.id).all();

          return json({
            ok: true,
            already_issued: true,
            receipt: existing,
            items: existingItems.results || [],
          }, 200);
        }

        // 対象期間（UTC日付範囲）の成功決済を集計
        const rangeStartIso = `${periodStartDate}T00:00:00.000Z`;
        const rangeEndIso = `${periodEndDate}T23:59:59.999Z`;

        const userCol = target_role === "host" ? "b.host_user_id" : "b.guest_user_id";
        let sql = `
          SELECT bp.id AS payment_id, bp.booking_id, bp.tx_type, bp.amount_jpy, bp.created_at,
                 b.booking_code
          FROM booking_payments bp
          JOIN bookings b ON b.id = bp.booking_id
          WHERE bp.status = 'succeeded'
            AND ${userCol} = ?
            AND bp.created_at >= ?
            AND bp.created_at <= ?
        `;
        const binds = [target_user_id, rangeStartIso, rangeEndIso];

        if (billing_cycle === "per_booking" && booking_id) {
          sql += ` AND bp.booking_id = ?`;
          binds.push(booking_id);
        }

        sql += ` ORDER BY bp.created_at ASC`;

        const paymentRows = await env.DB.prepare(sql).bind(...binds).all();
        const rows = paymentRows.results || [];

        if (rows.length === 0) {
          return json({
            ok: false,
            error: "指定期間・条件に該当する決済明細がありません",
            period_start_date: periodStartDate,
            period_end_date: periodEndDate,
          }, 404);
        }

        const formattedItems = rows.map((row, idx) => {
          const itemInfo = formatReceiptItemRow(row);
          return {
            id: makeId("ritm"),
            booking_id: row.booking_id,
            booking_payment_id: row.payment_id,
            description: itemInfo.description,
            amount_jpy: itemInfo.signedAmountJpy,
            sort_order: idx + 1,
          };
        });

        const totalJpy = formattedItems.reduce((sum, it) => sum + Number(it.amount_jpy), 0);
        if (totalJpy <= 0) {
          return json({
            ok: false,
            error: "集計合計が0円以下のため領収書を発行できません",
            total_jpy: totalJpy,
          }, 400);
        }

        const receiptId = makeId("rcp");
        const receiptNo = makeReceiptNo();
        const finalRecipientName =
          String(recipient_name || "").trim() ||
          user.name ||
          user.email ||
          target_user_id;

        const nowIso = new Date().toISOString();

        await env.DB.prepare(
          `INSERT INTO receipts (
            id, receipt_no, target_user_id, target_role, billing_cycle,
            period_start_date, period_end_date, recipient_name, issuer_name,
            currency, subtotal_jpy, tax_jpy, total_jpy, status, issued_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'JPY', ?, 0, ?, 'issued', ?)`
        ).bind(
          receiptId,
          receiptNo,
          target_user_id,
          target_role,
          billing_cycle,
          periodStartDate,
          periodEndDate,
          finalRecipientName,
          String(issuer_name || "salon-base").trim() || "salon-base",
          totalJpy,
          totalJpy,
          nowIso
        ).run();

        for (const item of formattedItems) {
          await env.DB.prepare(
            `INSERT INTO receipt_items (
              id, receipt_id, booking_id, booking_payment_id, description, amount_jpy, sort_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            item.id,
            receiptId,
            item.booking_id,
            item.booking_payment_id,
            item.description,
            item.amount_jpy,
            item.sort_order
          ).run();
        }

        return json({
          ok: true,
          already_issued: false,
          receipt: {
            id: receiptId,
            receipt_no: receiptNo,
            target_user_id,
            target_role,
            billing_cycle,
            period_start_date: periodStartDate,
            period_end_date: periodEndDate,
            recipient_name: finalRecipientName,
            issuer_name: String(issuer_name || "salon-base").trim() || "salon-base",
            currency: "JPY",
            subtotal_jpy: totalJpy,
            tax_jpy: 0,
            total_jpy: totalJpy,
            status: "issued",
            issued_at: nowIso,
          },
          items: formattedItems,
        }, 201);
      }

      // 5. 領収書取得
      const receiptMatch = url.pathname.match(/^\/api\/receipts\/([^/]+)$/);
      if (request.method === "GET" && receiptMatch) {
        const receiptId = receiptMatch[1];

        const receipt = await env.DB.prepare(
          `SELECT * FROM receipts WHERE id = ?`
        ).bind(receiptId).first();

        if (!receipt) {
          return json({ ok: false, error: "領収書が見つかりません" }, 404);
        }

        const items = await env.DB.prepare(
          `SELECT id, booking_id, booking_payment_id, description, amount_jpy, sort_order
           FROM receipt_items
           WHERE receipt_id = ?
           ORDER BY sort_order ASC`
        ).bind(receiptId).all();

        return json({
          ok: true,
          receipt,
          items: items.results || [],
        });
      }
          
    // 既存：サロン掲載エントリー＋メール通知
    if (url.pathname === "/api/entry" && request.method === "POST") {
      try {
        const b = await request.json();
        const salon = s(b.salon_name, 100);
        const person = s(b.person_name, 100);
        const email = s(b.email, 200);
        const phone = s(b.phone, 50);
        if (!salon || !person || !email || !phone)
          return json({ ok: false, error: "必須項目が未入力です" }, 400);
        await env.DB.prepare(
          "INSERT INTO owner_entries (created_at, salon_name, area, space_type, person_name, email, phone, image_key) VALUES (?,?,?,?,?,?,?,?)"
        )
          .bind(new Date().toISOString(), salon, s(b.area, 200), s(b.space_type, 50), person, email, phone, s(b.image_key, 200))
          .run();

        try {
          console.log("mail check", !!env.RESEND_API_KEY, !!env.NOTIFY_EMAIL);
          if (env.RESEND_API_KEY && env.NOTIFY_EMAIL) {
            const adminText = [
              "新しい掲載エントリーが届きました。",
              "",
              `サロン名: ${salon}`,
              `担当者: ${person}`,
              `エリア: ${s(b.area, 200)}`,
              `スペース: ${s(b.space_type, 50)}`,
              `メール: ${email}`,
              `電話: ${phone}`,
              `写真キー: ${s(b.image_key, 200) || "なし"}`,
            ].join("\n");

            const r1 = await fetch("https://api.resend.com/emails", {
              method: "POST",
              headers: {
                Authorization: `Bearer ${env.RESEND_API_KEY}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({
                from: "SalonBase <noreply@weblavo-tokyo.com>",
                to: [env.NOTIFY_EMAIL],
                subject: `【SalonBase】新規エントリー: ${salon}`,
                text: adminText,
              }),
            });
            if (!r1.ok) console.log("resend admin error", r1.status, await r1.text());

            const userText = [
              `${person} 様`,
              "",
              "この度はSalonBaseへ掲載エントリーをいただき、誠にありがとうございます。",
              "以下の内容で受け付けいたしました。",
              "",
              "────────────────────",
              `サロン名: ${salon}`,
              `ご担当者名: ${person}`,
              `エリア: ${s(b.area, 200)}`,
              `スペース種別: ${s(b.space_type, 50)}`,
              `メールアドレス: ${email}`,
              `お電話番号: ${phone}`,
              "────────────────────",
              "",
              "内容を確認のうえ、担当者より順次ご連絡いたします。",
              "今しばらくお待ちくださいませ。",
              "",
              "────────────────────",
              "SalonBase 運営事務局",
              "https://weblavo-tokyo.com",
              "────────────────────",
            ].join("\n");

            const r2 = await fetch("https://api.resend.com/emails", {
              method: "POST",
              headers: {
                Authorization: `Bearer ${env.RESEND_API_KEY}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({
                from: "SalonBase <noreply@weblavo-tokyo.com>",
                to: [email],
                reply_to: env.NOTIFY_EMAIL,
                subject: "【SalonBase】掲載エントリーを受け付けました",
                text: userText,
              }),
            });
            if (!r2.ok) console.log("resend user error", r2.status, await r2.text());
          }
        } catch (e) {}

        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: "保存に失敗しました" }, 500);
      }
    }

    // 追加：eKYC書類アップロード（AES-GCM暗号化 -> R2保存 -> D1記録）
    if (url.pathname === "/api/ekyc/upload" && request.method === "POST") {
      try {
        const form = await request.formData();
        const userId = s(form.get("userId"), 100);
        const docType = s(form.get("docType"), 50) || "drivers_license";
        const file = form.get("file");

        if (!userId || !file || typeof file === "string") {
          return json({ ok: false, error: "userId と書類ファイルが必要です" }, 400);
        }

        const allowedTypes = ["image/jpeg", "image/png", "application/pdf"];
        if (!allowedTypes.includes(file.type)) {
          return json({ ok: false, error: "JPEG / PNG / PDF のみ対応しています" }, 400);
        }
        if (file.size > 10 * 1024 * 1024) {
          return json({ ok: false, error: "10MB以下のファイルにしてください" }, 400);
        }

        const bucket = env.EKYC_BUCKET || env.IMAGES_BUCKET;
        const verificationId = crypto.randomUUID();
        const r2Key = `ekyc/${userId}/${verificationId}.enc`;
        const plainBuffer = await file.arrayBuffer();

        const aesKey = await importAesKey(env.EKYC_ENCRYPTION_KEY);
        const { cipherBuffer, ivBase64 } = await encryptBytes(aesKey, plainBuffer);

        await bucket.put(r2Key, cipherBuffer, {
          httpMetadata: { contentType: "application/octet-stream" },
        });

        const nowIso = new Date().toISOString();
        const expiresIso = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        await env.DB.batch([
          env.DB.prepare(
            `INSERT INTO ekyc_verifications
             (id, user_id, doc_type, mime_type, r2_key, iv_b64, status, expires_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, 'pending_review', ?, ?, ?)`
          ).bind(
            verificationId,
            userId,
            docType,
            file.type,
            r2Key,
            ivBase64,
            expiresIso,
            nowIso,
            nowIso
          ),
          env.DB.prepare(
            `UPDATE users SET kyc_status = 'pending_review', updated_at = ? WHERE id = ?`
          ).bind(nowIso, userId),
        ]);

        return json({ ok: true, verificationId, status: "pending_review" });
      } catch (e) {
        return json({ ok: false, error: "本人確認書類の保存に失敗しました" }, 500);
      }
    }

    // 追加：eKYC書類閲覧（審査待ちのみ復号して一時表示）
    const viewMatch = url.pathname.match(/^\/api\/ekyc\/([^/]+)\/view$/);
    if (request.method === "GET" && viewMatch) {
      try {
        const verificationId = viewMatch[1];
        const record = await env.DB.prepare(
          `SELECT id, r2_key, iv_b64, mime_type, status FROM ekyc_verifications WHERE id = ?`
        )
          .bind(verificationId)
          .first();

        if (!record || record.status !== "pending_review" || !record.r2_key || !record.iv_b64) {
          return json({ ok: false, error: "表示できる書類がありません" }, 404);
        }

        const bucket = env.EKYC_BUCKET || env.IMAGES_BUCKET;
        const obj = await bucket.get(record.r2_key);
        if (!obj) {
          return json({ ok: false, error: "R2データが見つかりません" }, 404);
        }

        const cipherBuffer = await obj.arrayBuffer();
        const aesKey = await importAesKey(env.EKYC_ENCRYPTION_KEY);
        const plainBuffer = await decryptBytes(aesKey, cipherBuffer, record.iv_b64);

        return new Response(plainBuffer, {
          status: 200,
          headers: {
            "Content-Type": record.mime_type,
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "X-Content-Type-Options": "nosniff",
          },
        });
      } catch (e) {
        return json({ ok: false, error: "復号処理に失敗しました" }, 500);
      }
    }

    // 追加：eKYC審査完了（承認 or 差し戻し -> R2から即削除 -> D1更新）
    const reviewMatch = url.pathname.match(/^\/api\/ekyc\/([^/]+)\/review$/);
    if (request.method === "POST" && reviewMatch) {
      try {
        const verificationId = reviewMatch[1];
        const b = await request.json();
        const decision = b.decision;
        const reviewerId = s(b.reviewerId, 100) || "admin";
        const rejectReason = s(b.rejectReason, 300) || "不備あり";

        if (decision !== "approved" && decision !== "rejected") {
          return json({ ok: false, error: "decision は approved または rejected を指定してください" }, 400);
        }

        const record = await env.DB.prepare(
          `SELECT id, user_id, r2_key, status FROM ekyc_verifications WHERE id = ?`
        )
          .bind(verificationId)
          .first();

        if (!record) {
          return json({ ok: false, error: "審査レコードが見つかりません" }, 404);
        }

        // ★ R2から対象ファイルを即削除
        const bucket = env.EKYC_BUCKET || env.IMAGES_BUCKET;
        if (record.r2_key) {
          await bucket.delete(record.r2_key);
        }

        const nowIso = new Date().toISOString();

        await env.DB.batch([
          env.DB.prepare(
            `UPDATE ekyc_verifications
             SET status = ?,
                 reject_reason = ?,
                 reviewed_by = ?,
                 reviewed_at = ?,
                 deleted_at = ?,
                 r2_key = NULL,
                 iv_b64 = NULL,
                 updated_at = ?
             WHERE id = ?`
          ).bind(
            decision,
            decision === "rejected" ? rejectReason : null,
            reviewerId,
            nowIso,
            nowIso,
            nowIso,
            verificationId
          ),
          env.DB.prepare(
            `UPDATE users SET kyc_status = ?, updated_at = ? WHERE id = ?`
          ).bind(decision, nowIso, record.user_id),
        ]);

        return json({
          ok: true,
          verificationId,
          status: decision,
          r2Deleted: true,
          deletedAt: nowIso,
        });
      } catch (e) {
        return json({ ok: false, error: "審査処理に失敗しました" }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  },
};
