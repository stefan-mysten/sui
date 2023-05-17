// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Types } from '@amplitude/analytics-browser';
import { getProductAnalyticsConfig } from '@mysten/core';

import { ampli } from './ampli';

const IS_PROD_ENV = import.meta.env.PROD;

export async function initAmplitude() {
    const { disableCookies } = await getProductAnalyticsConfig(IS_PROD_ENV);
    ampli.load({
        environment: IS_PROD_ENV ? 'production' : 'development',
        disabled: !IS_PROD_ENV,
        client: {
            configuration: {
                logLevel: IS_PROD_ENV
                    ? Types.LogLevel.Warn
                    : Types.LogLevel.Debug,
                disableCookies,
            },
        },
    });
}
