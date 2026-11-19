export async function onRequestPost(context) {
  try {
    const { request, env } = context;

    if (!env.IMAGES_BUCKET || !env.DB) {
      return new Response(
        JSON.stringify({
          error: "R2 (IMAGES_BUCKET) または D1 (DB) のバインディングが見つかりません。wrangler.toml のデプロイを確認してください。",
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }

    const formData = await request.formData();
    const file = formData.get("file");
    const salonId = formData.get("salon_id") || null;

    if (!file || typeof file === "string") {
      return new Response(
        JSON.stringify({ error: "画像ファイル（file）が送信されていません。" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    const ext = file.name && file.name.includes(".")
      ? file.name.split(".").pop().toLowerCase()
      : "jpg";
    const key = `salons/${Date.now()}-${crypto.randomUUID()}.${ext}`;
    const arrayBuffer = await file.arrayBuffer();

    await env.IMAGES_BUCKET.put(key, arrayBuffer, {
      httpMetadata: {
        contentType: file.type || "image/jpeg",
      },
    });

    // ※ salon_images テーブルの実際のカラム名に合わせて列名を確認してください
    await env.DB.prepare(
      "INSERT INTO salon_images (salon_id, image_key, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)"
    )
      .bind(salonId, key)
      .run();

    return new Response(
      JSON.stringify({
        ok: true,
        key,
        salon_id: salonId,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ error: err.message || "アップロード中にエラーが発生しました。" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}
