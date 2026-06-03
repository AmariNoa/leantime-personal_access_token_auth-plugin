<?php

/**
 * PersonalAccessTokenAuth — plugin entry point.
 *
 * Registers a listener on the `before_api_request` event, which Leantime's
 * AuthCheck middleware fires for every JSON-RPC/API request AFTER all plugins
 * are loaded and BEFORE the auth guards run. There we validate a Bearer
 * Personal Access Token and establish the token owner's session, so the API
 * can be called as that human user. (Leantime core only accepts X-API-KEY on
 * /api/jsonrpc; this plugin adds Bearer/PAT support using core primitives.)
 *
 * SPDX-FileCopyrightText: 2026 AmariNoa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace Leantime\Plugins\PersonalAccessTokenAuth;

use Leantime\Core\Events\EventDispatcher;
use Leantime\Plugins\PersonalAccessTokenAuth\Services\BearerTokenAuthenticator;

EventDispatcher::add_event_listener(
    'leantime.core.middleware.apiAuth.handle.before_api_request',
    function ($payload = null): void {
        app()->make(BearerTokenAuthenticator::class)->authenticate();
    }
);

// Add a "Personal Access Tokens" tab to the Account Settings page (editOwn),
// alongside My Profile / Security / Settings / Notifications / Theme. These two
// template events fire inside editOwn.blade.php; listeners echo their HTML
// inline (the tab header <li> and the tab content pane).
EventDispatcher::add_event_listener(
    'leantime.domain.users.templates.editOwn.tabs',
    function ($payload = null): void {
        app()->make(Services\TokenTab::class)->renderTabHeader();
    }
);
EventDispatcher::add_event_listener(
    'leantime.domain.users.templates.editOwn.tabsContent',
    function ($payload = null): void {
        app()->make(Services\TokenTab::class)->renderTabContent();
    }
);

// Admin: add an "Access Tokens" item to the Company > Administration menu,
// linking to the plugin's admin page (all users' tokens + per-user filter).
EventDispatcher::add_filter_listener(
    'leantime.domain.menu.repositories.menu.*.menuStructures',
    function ($menuStructure, $params = []) {
        if (is_array($menuStructure) && isset($menuStructure['company']) && is_array($menuStructure['company'])) {
            foreach ($menuStructure['company'] as &$section) {
                if (is_array($section)
                    && ($section['id'] ?? '') === 'administration'
                    && isset($section['submenu']) && is_array($section['submenu'])) {
                    $section['submenu'][] = [
                        'type' => 'item',
                        'module' => 'personalAccessTokenAuth',
                        'role' => 'admin',
                        'title' => '<i class="fa fa-fw fa-key"></i> Access Tokens',
                        'icon' => 'fa fa-fw fa-key',
                        'tooltip' => 'Manage all personal access tokens',
                        'href' => '/personalAccessTokenAuth/admin',
                        'active' => ['admin'],
                    ];
                }
            }
            unset($section);
        }

        return $menuStructure;
    }
);

// Keep the Company menu active when viewing the plugin's admin page.
EventDispatcher::add_filter_listener(
    'leantime.domain.menu.repositories.menu.*.menuSections',
    function ($sections, $params = []) {
        if (is_array($sections)) {
            $sections['personalAccessTokenAuth.admin'] = 'company';
        }

        return $sections;
    }
);
