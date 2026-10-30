export interface TaxonomyItem {
	id: number;
	name: string;
	feature_url?: string | null;
}

export async function listCategories(db: D1DatabaseSession): Promise<TaxonomyItem[]> {
	return (await db.prepare('SELECT category_id AS id, name FROM Categories ORDER BY name').all<TaxonomyItem>()).results;
}

export async function listFeatures(db: D1DatabaseSession): Promise<TaxonomyItem[]> {
	return (await db.prepare('SELECT feature_id AS id, name, feature_url FROM CloudflareFeatures ORDER BY name').all<TaxonomyItem>()).results;
}
