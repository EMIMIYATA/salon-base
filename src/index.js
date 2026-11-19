const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
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
    return env.ASSETS.fetch(request);
  },
};
