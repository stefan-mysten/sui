// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

type ProductAnalyticsConfigResponse = { disableCookies: boolean };

export async function getProductAnalyticsConfig(isProductionEnv: boolean) {
    const appsBackendUrl = isProductionEnv
        ? 'https://apps-backend.sui.io'
        : 'http://localhost:3003';

    const response = await fetch(`${appsBackendUrl}/product-analytics`);
    if (!response.ok) {
        throw new Error(
            `Received ${response.status} status code trying to fetch the analytics configuration.`
        );
    }

    const config: ProductAnalyticsConfigResponse = await response.json();
    return config;
}
