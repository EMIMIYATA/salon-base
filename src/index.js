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

function safeJsonArray(str, fallback = []) {
  try {
    const parsed = JSON.parse(str || "[]");
    return Array.isArray(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

// ---- 管理者認証（パスワードと秘密鍵はCloudflareの変数のみ） ----
function getAdminSecret(env) {
  return String(env.ADMIN_TOKEN_SECRET || "");
}

function verifyAdminPassword(password, env) {
  const input = String(password || "");
  const expected = String(env.ADMIN_PASSWORD || "");
  if (!expected || !input) return false;
  if (input.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < input.length; i++) {
    diff |= input.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

async function hmacKey(secret, usage) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    [usage]
  );
}

async function createAdminToken(env) {
  const secret = getAdminSecret(env);
  if (!secret) throw new Error("ADMIN_TOKEN_SECRET が未設定です");
  const now = Date.now();
  const payload = btoa(
    JSON.stringify({ role: "admin", iat: now, exp: now + 24 * 60 * 60 * 1000 })
  );
  const key = await hmacKey(secret, "sign");
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  const sigHex = Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${payload}.${sigHex}`;
}

async function verifyAdminToken(request, env) {
  try {
    const secret = getAdminSecret(env);
    if (!secret) return false;
    const auth = request.headers.get("Authorization") || "";
    const match = auth.match(/^Bearer\s+(.+)$/i);
    if (!match) return false;
    const parts = match[1].trim().split(".");
    if (parts.length !== 2) return false;
    const [payload, sigHex] = parts;

    const key = await hmacKey(secret, "verify");
    const sigBytes = new Uint8Array(
      (sigHex.match(/.{1,2}/g) || []).map((h) => parseInt(h, 16))
    );
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      new TextEncoder().encode(payload)
    );
    if (!valid) return false;

    const data = JSON.parse(atob(payload));
    return data?.role === "admin" && Number(data.exp) > Date.now();
  } catch {
    return false;
  }
}

async function sendMail(env, to, subject, text) {
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: "SalonBase <noreply@weblavo-tokyo.com>",
      to: [to],
      subject,
      text,
    }),
  });
  if (!r.ok) console.log("resend error", r.status, await r.text());
  return r.ok;
}// パスワードをソルト付きSHA-256でハッシュ化するヘルパー
async function hashPassword(password, saltHex = null) {
  const saltBytes = saltHex
    ? Uint8Array.from(saltHex.match(/.{1,2}/g).map((b) => parseInt(b, 16)))
    : crypto.getRandomValues(new Uint8Array(16));

  const resolvedSaltHex = Array.from(saltBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const enc = new TextEncoder();
  const data = enc.encode(`${resolvedSaltHex}:${password}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const hashHex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return { saltHex: resolvedSaltHex, hashHex };
}

// 振り分け番号を生成するヘルパー（例: SB-2026-4821）
function generateOwnerCode() {
  const year = new Date().getFullYear();
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `SB-${year}-${rand}`;
}


export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // ---- ログイン ----
    if (path === "/api/auth/login" && method === "POST") {
      try {
        const body = await request.json().catch(() => ({}));
        if (!verifyAdminPassword(body.password, env)) {
          return json({ ok: false, error: "パスワードが正しくありません" }, 401);
        }
        const token = await createAdminToken(env);
        return json({ ok: true, token });
      } catch (err) {
        return json({ ok: false, error: "ログイン処理に失敗しました" }, 500);
      }
    }

    // ---- 画像アップロード ----
    if (path === "/api/upload" && method === "POST") {
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
        // ---- AI文章生成 ----
    if (path === "/api/ai/generate-copy" && method === "POST") {
      try {
        if (!env.AI) {
          return json({ ok: false, error: "Workers AI (env.AI) が設定されていません" }, 500);
        }
        const body = await request.json().catch(() => ({}));
        const target = body.target === "rules" ? "rules" : "description";
        const salon = body.salon || {};

        const prompt =
          target === "rules"
            ? `レンタルサロンの「入室方法・ご利用ルール」を、箇条書き5〜7項目の日本語で作成してください。
サロン名: ${salon.name || ""}
エリア: ${salon.area || ""}
設備: ${salon.amenities || ""}
オーナーのメモ: ${salon.rules || ""}`
            : `レンタルサロンの「お部屋・空間の紹介文」を、上品で信頼感のある日本語で150〜250文字で作成してください。
サロン名: ${salon.name || ""}
エリア・最寄駅: ${salon.area || ""} ${salon.station || ""}
1時間料金: ${salon.price || ""}円
ジャンル: ${salon.genre || ""}
設備: ${salon.amenities || ""}
オーナーのメモ: ${salon.description || ""}`;

        const systemPrompt = `あなたはレンタルサロンの掲載文を書く日本語のライターです。
- オーナーのメモがある場合は、その意味と事実を変えずに、読みやすく上品な文章に整えてください。
- 入力にない設備・条件・事実を勝手に付け足さないでください。誇張もしないでください。
- 前置きや解説は書かず、本文のみを出力してください。`;

        const result = await env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", {
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: prompt },
          ],
          max_tokens: 500,
        });

        const text = String(
          result?.response ??
            result?.output_text ??
            result?.result?.response ??
            result?.choices?.[0]?.message?.content ??
            ""
        ).trim();

        if (!text) {
          console.log("ai raw", JSON.stringify(result));
          return json({ ok: false, error: "文章を生成できませんでした。" }, 500);
        }
        return json({ ok: true, text });
      } catch (err) {
        console.log("ai error", String(err));
        return json(
          { ok: false, error: `AI生成エラー: ${err?.message || String(err)}` },
          500
        );
      }
    }

    // ---- 画像配信 ----
    if (path.startsWith("/api/images/") && method === "GET") {
      try {
        const key = decodeURIComponent(path.replace(/^\/api\/images\//, ""));
        if (!key || key.includes("..")) {
          return json({ ok: false, error: "不正なキーです" }, 400);
        }
        const obj = await env.IMAGES_BUCKET.get(key);
        if (!obj) return json({ ok: false, error: "画像が見つかりません" }, 404);
        const headers = new Headers();
        if (obj.httpMetadata?.contentType) {
          headers.set("Content-Type", obj.httpMetadata.contentType);
        }
        headers.set("Cache-Control", "public, max-age=3600");
        return new Response(obj.body, { status: 200, headers });
      } catch {
        return json({ ok: false, error: "画像取得に失敗しました" }, 500);
      }
    }

    // ---- サロン一覧 ----
    if (path === "/api/salons" && method === "GET") {
      try {
        const rows = await env.DB.prepare(
          `SELECT * FROM published_salons ORDER BY id DESC`
        ).all();
                const photoRows = await env.DB.prepare(
          `SELECT salon_id, image_key FROM salon_photos ORDER BY salon_id, sort_order ASC`
        ).all();
        const photoMap = {};
        for (const p of photoRows.results || []) {
          (photoMap[p.salon_id] ||= []).push(`/api/images/${encodeURIComponent(p.image_key)}`);
        }

        const salons = (rows.results || []).map((r) => ({
          id: `db_${r.id}`,
          name: r.name,
          area: r.area,
          station: r.station,
          pricePerHour: Number(r.price_per_hour || 1500),
          rating: Number(r.rating || 4.9),
          reviewCount: Number(r.review_count || 1),
          availabilityBadge: r.availability_badge || "本日空きあり",
          genres: safeJsonArray(r.genres_json, ["エステ・リラク"]),
          equipment: safeJsonArray(r.equipment_json, ["完全個室"]),
          image:
            r.image_url ||
            (r.image_key ? `/api/images/${encodeURIComponent(r.image_key)}` : ""),
          image_key: r.image_key || "",
                    images: photoMap[r.id] || (r.image_key ? [`/api/images/${encodeURIComponent(r.image_key)}`] : []),
          description: r.description || "",
          freeAmenities: safeJsonArray(r.free_amenities_json, []),
          entryRules: r.entry_rules || "",
          bookedHours: safeJsonArray(r.booked_hours_json, []),
        }));
        return json({ ok: true, salons });
      } catch (e) {
        return json({ ok: false, error: "サロン一覧の取得に失敗しました" }, 500);
      }
    }

    // ---- サロン登録（ログイン必須） ----
    if (path === "/api/salons" && method === "POST") {
      try {
        if (!(await verifyAdminToken(request, env))) {
          return json({ ok: false, error: "認証が必要です。再ログインしてください。" }, 401);
        }
        const b = await request.json();
        const name = s(b.name, 120);
        const area = s(b.area, 80);
        const station = s(b.station, 120);
        const pricePerHour = Number(b.pricePerHour);
        if (!name || !area || !station || !Number.isFinite(pricePerHour) || pricePerHour <= 0) {
          return json({ ok: false, error: "サロン名・エリア・最寄り駅・1時間料金は必須です" }, 400);
        }
        const genres =
          Array.isArray(b.genres) && b.genres.length
            ? b.genres.map((x) => s(x, 50))
            : ["エステ・リラク"];
        const equipment = Array.isArray(b.equipment) ? b.equipment.map((x) => s(x, 50)) : [];
        const freeAmenities =
          Array.isArray(b.freeAmenities) && b.freeAmenities.length
            ? b.freeAmenities.map((x) => s(x, 120))
            : ["施術スペース設備完備"];
        const bookedHours = Array.isArray(b.bookedHours)
          ? b.bookedHours.map((x) => s(x, 20))
          : [];
                const imageKeys = Array.isArray(b.image_keys)
          ? b.image_keys.map((x) => s(x, 250)).filter(Boolean).slice(0, 20)
          : [];
        const imageKey = s(b.image_key, 250) || imageKeys[0] || "";
        const rawImage = s(b.image, 500);
        const imageUrl =
          rawImage || (imageKey ? `/api/images/${encodeURIComponent(imageKey)}` : "");
        const nowIso = new Date().toISOString();

        const ins = await env.DB.prepare(
          `INSERT INTO published_salons (
            name, area, station, price_per_hour, rating, review_count,
            availability_badge, genres_json, equipment_json, image_url, image_key,
            description, free_amenities_json, entry_rules, booked_hours_json,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            name,
            area,
            station,
            Math.round(pricePerHour),
            Number(b.rating) || 4.9,
            Number(b.reviewCount) || 1,
            s(b.availabilityBadge, 40) || "本日空きあり",
            JSON.stringify(genres),
            JSON.stringify(equipment),
            imageUrl,
            imageKey,
            s(b.description, 1000) || "プライベートサロン空間です。",
            JSON.stringify(freeAmenities),
            s(b.entryRules, 1000) || "ご予約時間に合わせてご入室・ご退室ください。",
            JSON.stringify(bookedHours),
            nowIso,
            nowIso
          )
          .run();
        const newId = ins.meta?.last_row_id;
        for (let i = 0; i < imageKeys.length; i++) {
          await env.DB.prepare(
            `INSERT INTO salon_photos (salon_id, image_key, sort_order, created_at) VALUES (?, ?, ?, ?)`
          ).bind(newId, imageKeys[i], i, nowIso).run();
        }

        return json({ ok: true, id: ins.meta?.last_row_id, imageUrl }, 201);
      } catch (e) {
        return json({ ok: false, error: "サロン情報の保存に失敗しました" }, 500);
      }
    }

    // ---- 掲載エントリー＋メール通知 ----
    if (path === "/api/entry" && method === "POST") {
  try {
    const b = await request.json();
    const salon = s(b.salon_name, 100);
    const person = s(b.person_name, 100);
    const email = s(b.email, 200);
    const phone = s(b.phone, 50);
    const rawPassword = String(b.password || "");

    if (!salon || !person || !email || !phone) {
      return json({ ok: false, error: "必須項目が未入力です" }, 400);
    }
    if (rawPassword.length < 6) {
      return json({ ok: false, error: "ログインパスワードは6文字以上で設定してください" }, 400);
    }

    const ownerCode = generateOwnerCode();
    const { saltHex, hashHex } = await hashPassword(rawPassword);
    const createdAt = new Date().toISOString();

    await env.DB.prepare(
      `INSERT INTO owner_entries
        (created_at, salon_name, area, space_type, person_name, email, phone, image_key, owner_code, password_hash, password_salt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        createdAt,
        salon,
        s(b.area, 200),
        s(b.space_type, 50),
        person,
        email,
        phone,
        s(b.image_key, 200),
        ownerCode,
        hashHex,
        saltHex
      )
      .run();

    const adminUrl = "https://salon-base.emikurekura.workers.dev/admin";

    // 運営宛て通知メール（パスワードは記載せず、番号と管理画面URLを案内）
    try {
      if (env.RESEND_API_KEY && env.NOTIFY_EMAIL) {
        const adminText = [
          "新しい掲載エントリーが届きました。",
          "",
          `割り当て番号: ${ownerCode}`,
          `サロン名: ${salon}`,
          `担当者: ${person}`,
          `エリア: ${s(b.area, 200)}`,
          `メール: ${email}`,
          `電話: ${phone}`,
          "",
          "▼ 管理画面（SalonBase Owner Console）",
          adminUrl
        ].join("\n");

        await sendMail(env, env.NOTIFY_EMAIL, `【SalonBase】新規エントリー（${ownerCode}）：${salon}`, adminText);
      }
    } catch (mailErr) {
      console.error("Notify mail error:", mailErr);
    }

    // フロント側へ「割り当て番号」と「管理画面URL」を返して誘導しやすくする
    return json({
      ok: true,
      owner_code: ownerCode,
      admin_url: adminUrl
    });
  } catch (err) {
    return json({ ok: false, error: String(err?.message || err) }, 500);
  }
}
if (path === "/api/owner/login" && method === "POST") {
  try {
    const b = await request.json();
    const ownerCode = String(b.owner_code || "").trim().toUpperCase();
    const rawPassword = String(b.password || "");

    if (!ownerCode || !rawPassword) {
      return json({ ok: false, error: "番号とパスワードを入力してください" }, 400);
    }

    const row = await env.DB.prepare(
      "SELECT id, owner_code, salon_name, person_name, password_hash, password_salt FROM owner_entries WHERE owner_code = ? LIMIT 1"
    )
      .bind(ownerCode)
      .first();

    if (!row || !row.password_hash || !row.password_salt) {
      return json({ ok: false, error: "番号またはパスワードが正しくありません" }, 401);
    }

    const { hashHex } = await hashPassword(rawPassword, row.password_salt);
    if (hashHex !== row.password_hash) {
      return json({ ok: false, error: "番号またはパスワードが正しくありません" }, 401);
    }

    return json({
      ok: true,
      owner: {
        id: row.id,
        owner_code: row.owner_code,
        salon_name: row.salon_name,
        person_name: row.person_name
      }
    });
  } catch (err) {
    return json({ ok: false, error: String(err?.message || err) }, 500);
  }
}

    // ---- 1. 予約作成 ----
    if (method === "POST" && path === "/api/bookings") {
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
      const paymentDueAt = new Date(
        Date.now() + Number(payment_due_minutes) * 60 * 1000
      ).toISOString();

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

    // ---- 2. 手数料先払い完了 ----
    const payMatch = path.match(/^\/api\/bookings\/([^/]+)\/pay-fee$/);
    if (method === "POST" && payMatch) {
      const bookingId = payMatch[1];
      const body = await request.json().catch(() => ({}));
      const provider = body.provider || "manual_or_gateway";
      const providerTxId = body.provider_tx_id || null;

      const booking = await env.DB.prepare(
        `SELECT * FROM bookings WHERE id = ?`
      ).bind(bookingId).first();

      if (!booking) return json({ ok: false, error: "予約が見つかりません" }, 404);

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
         SET status = 'confirmed', fee_payment_status = 'paid', paid_at = ?, updated_at = ?
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

    // ---- 3. キャンセル ----
    const cancelMatch = path.match(/^\/api\/bookings\/([^/]+)\/cancel$/);
    if (method === "POST" && cancelMatch) {
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

      if (!booking) return json({ ok: false, error: "予約が見つかりません" }, 404);

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
        nextFeePaymentStatus = "unpaid";
        policyApplied = "unpaid_pending_cancel";
      } else if (actorRole === "host" || actorRole === "admin") {
        refundAmount = prepaidAmount;
        nextFeePaymentStatus = "refunded";
        policyApplied = "host_or_admin_full_refund";
      } else if (minutesBeforeStart >= freeBeforeMin) {
        refundAmount = prepaidAmount;
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
          `INSERT INTO booking_payments (id, booking_id, tx_type, amount_jpy, provider, status)
           VALUES (?, ?, 'refund', ?, 'manual_or_gateway', 'succeeded')`
        ).bind(makeId("pay"), bookingId, refundAmount).run();
      }
      if (penaltyAmount > 0) {
        await env.DB.prepare(
          `INSERT INTO booking_payments (id, booking_id, tx_type, amount_jpy, provider, status)
           VALUES (?, ?, 'penalty_capture', ?, 'manual_or_gateway', 'succeeded')`
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

    // ---- 4. 領収書発行 ----
    if (method === "POST" && path === "/api/receipts/issue") {
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
      if (!user) return json({ ok: false, error: "対象ユーザーが見つかりません" }, 404);

      let effectiveAnchorDate = anchor_date;
      if (billing_cycle === "per_booking") {
        if (!booking_id) {
          return json({ ok: false, error: "都度発行（per_booking）には booking_id が必要です" }, 400);
        }
        const targetBooking = await env.DB.prepare(
          `SELECT * FROM bookings WHERE id = ?`
        ).bind(booking_id).first();
        if (!targetBooking) return json({ ok: false, error: "対象予約が見つかりません" }, 404);
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

      const existing = await env.DB.prepare(
        `SELECT * FROM receipts
         WHERE target_user_id = ? AND target_role = ? AND billing_cycle = ?
           AND period_start_date = ? AND period_end_date = ? AND status = 'issued'
         ORDER BY created_at DESC LIMIT 1`
      ).bind(target_user_id, target_role, billing_cycle, periodStartDate, periodEndDate).first();

      if (existing) {
        const existingItems = await env.DB.prepare(
          `SELECT id, booking_id, booking_payment_id, description, amount_jpy, sort_order
           FROM receipt_items WHERE receipt_id = ? ORDER BY sort_order ASC`
        ).bind(existing.id).all();
        return json({
          ok: true,
          already_issued: true,
          receipt: existing,
          items: existingItems.results || [],
        }, 200);
      }

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
        const info = formatReceiptItemRow(row);
        return {
          id: makeId("ritm"),
          booking_id: row.booking_id,
          booking_payment_id: row.payment_id,
          description: info.description,
          amount_jpy: info.signedAmountJpy,
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
        String(recipient_name || "").trim() || user.name || user.email || target_user_id;
      const finalIssuer = String(issuer_name || "salon-base").trim() || "salon-base";
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
        finalIssuer,
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
          issuer_name: finalIssuer,
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

    // ---- 5. 領収書取得 ----
    const receiptMatch = path.match(/^\/api\/receipts\/([^/]+)$/);
    if (method === "GET" && receiptMatch) {
      const receiptId = receiptMatch[1];
      const receipt = await env.DB.prepare(
        `SELECT * FROM receipts WHERE id = ?`
      ).bind(receiptId).first();
      if (!receipt) return json({ ok: false, error: "領収書が見つかりません" }, 404);
      const items = await env.DB.prepare(
        `SELECT id, booking_id, booking_payment_id, description, amount_jpy, sort_order
         FROM receipt_items WHERE receipt_id = ? ORDER BY sort_order ASC`
      ).bind(receiptId).all();
      return json({ ok: true, receipt, items: items.results || [] });
    }

    // ---- それ以外は画面（HTMLなど）を返す ----
    if (path.startsWith("/api/")) {
      return json({ ok: false, error: "Not Found" }, 404);
    }
    return env.ASSETS.fetch(request);
  },
};
