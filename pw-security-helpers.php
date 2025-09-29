<?php
/*
 * Plugin Name: PW Security Helpers
 * Plugin URI: https://example.com
 * Description: Provide a few simple security hardening options to make your WordPress site a little safer.  You can selectively disable REST API user enumeration, author enumeration, XML‑RPC, and optionally require that visitors be logged in before the REST API will respond.  These options live under the WordPress “Settings” menu.
 * Author: Tyrus Christiana
 * Version: 1.1.0
 * License: GPL‑2.0+
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: pw-security-helpers
 * Domain Path: /languages
 */

// Exit if accessed directly.
if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('PW_Security_Helpers')) {
    /**
     * Main plugin class.
     *
     * This class encapsulates all of the functionality of the plugin. It registers
     * a settings page, stores options in the database, and hooks into WordPress
     * runtime in order to block certain requests when configured to do so.
     */
    class PW_Security_Helpers
    {
        /**
         * Name of the option that holds our settings.
         *
         * @var string
         */
        private $option_name = 'pwsh_options';

        /**
         * Cached copy of the current option values.
         *
         * @var array
         */
        private $options = array();

        /**
         * Constructor. Loads options, registers hooks and admin pages.
         */
        public function __construct()
        {
            $defaults = $this->get_default_options();
            $stored_options = get_option($this->option_name, array());

            if (!is_array($stored_options)) {
                $stored_options = array();
            }

            $this->options = $this->merge_options($defaults, $stored_options);

            // Block malicious or unwanted requests early.
            add_action('init', array($this, 'maybe_block_requests'));

            // If requested, disable XML-RPC completely.
            if (!empty($this->options['disable_xmlrpc'])) {
                add_filter('xmlrpc_enabled', '__return_false');
            }

            // If requested, restrict access to the REST API to logged in users only.
            if (!empty($this->options['restrict_rest_api'])) {
                add_filter('rest_authentication_errors', array($this, 'maybe_restrict_rest_api'));
            }

            // Send configured HTTP security headers.
            add_action('send_headers', array($this, 'maybe_send_security_headers'));

            // Admin UI hooks. Only load in admin.
            if (is_admin()) {
                add_action('admin_menu', array($this, 'add_settings_page'));
                add_action('admin_init', array($this, 'register_settings'));
            }
        }

        /**
         * Provide default option values for the plugin.
         *
         * @return array
         */
        private function get_default_options()
        {
            return array(
                'block_user_endpoint' => 0,
                'block_author_enum'   => 0,
                'disable_xmlrpc'      => 0,
                'restrict_rest_api'   => 0,
                'security_headers'    => array(
                    'hsts' => array(
                        'enabled'            => 0,
                        'max_age'            => 31536000,
                        'include_subdomains' => 1,
                        'preload'            => 0,
                    ),
                    'content_security_policy' => array(
                        'enabled' => 0,
                        'value'   => "default-src 'self';",
                    ),
                    'x_frame_options' => array(
                        'enabled' => 0,
                        'value'   => 'SAMEORIGIN',
                    ),
                    'x_content_type_options' => array(
                        'enabled' => 0,
                    ),
                    'referrer_policy' => array(
                        'enabled' => 0,
                        'value'   => 'no-referrer-when-downgrade',
                    ),
                    'permissions_policy' => array(
                        'enabled' => 0,
                        'value'   => '',
                    ),
                ),
            );
        }

        /**
         * Recursively merge stored options into defaults while preserving structure.
         *
         * @param array $defaults Default values.
         * @param array $saved    Stored option values.
         * @return array
         */
        private function merge_options(array $defaults, array $saved)
        {
            foreach ($saved as $key => $value) {
                if (array_key_exists($key, $defaults)) {
                    if (is_array($defaults[$key]) && is_array($value)) {
                        $defaults[$key] = $this->merge_options($defaults[$key], $value);
                    } else {
                        $defaults[$key] = $value;
                    }
                } else {
                    $defaults[$key] = $value;
                }
            }

            return $defaults;
        }

        /**
         * Definitions for supported HTTP security headers and their UI metadata.
         *
         * @return array
         */
        private function get_security_header_definitions()
        {
            return array(
                'hsts' => array(
                    'label'       => __('Strict-Transport-Security (HSTS)', 'pw-security-helpers'),
                    'description' => __('Force HTTPS by instructing browsers to only connect over TLS.', 'pw-security-helpers'),
                    'fields'      => array(
                        'max_age' => array(
                            'type'        => 'number',
                            'label'       => __('Max-Age (seconds)', 'pw-security-helpers'),
                            'description' => __('Time in seconds the browser should enforce HTTPS connections.', 'pw-security-helpers'),
                            'attributes'  => array(
                                'min'  => 0,
                                'step' => 1,
                            ),
                        ),
                        'include_subdomains' => array(
                            'type'  => 'checkbox',
                            'label' => __('Include subdomains', 'pw-security-helpers'),
                        ),
                        'preload' => array(
                            'type'        => 'checkbox',
                            'label'       => __('Mark for preload list', 'pw-security-helpers'),
                            'description' => __('Only enable after submitting to hstspreload.org and validating eligibility.', 'pw-security-helpers'),
                        ),
                    ),
                ),
                'content_security_policy' => array(
                    'label'       => __('Content-Security-Policy', 'pw-security-helpers'),
                    'description' => __('Control which resources the browser is allowed to load.', 'pw-security-helpers'),
                    'fields'      => array(
                        'value' => array(
                            'type'        => 'textarea',
                            'label'       => __('Policy', 'pw-security-helpers'),
                            'description' => __('Provide a full CSP directive string, e.g., default-src \'self\'; img-src \'self\' data:.', 'pw-security-helpers'),
                        ),
                    ),
                ),
                'x_frame_options' => array(
                    'label'       => __('X-Frame-Options', 'pw-security-helpers'),
                    'description' => __('Mitigate clickjacking by controlling iframe embedding.', 'pw-security-helpers'),
                    'fields'      => array(
                        'value' => array(
                            'type'        => 'text',
                            'label'       => __('Header value', 'pw-security-helpers'),
                            'description' => __('Common values include SAMEORIGIN or DENY. Provide a custom directive if needed.', 'pw-security-helpers'),
                        ),
                    ),
                ),
                'x_content_type_options' => array(
                    'label'       => __('X-Content-Type-Options', 'pw-security-helpers'),
                    'description' => __('Stop browsers from MIME-sniffing content types.', 'pw-security-helpers'),
                    'fields'      => array(),
                ),
                'referrer_policy' => array(
                    'label'       => __('Referrer-Policy', 'pw-security-helpers'),
                    'description' => __('Control how much referrer information accompanies requests.', 'pw-security-helpers'),
                    'fields'      => array(
                        'value' => array(
                            'type'    => 'select',
                            'label'   => __('Policy value', 'pw-security-helpers'),
                            'options' => array(
                                'no-referrer'                     => __('no-referrer', 'pw-security-helpers'),
                                'no-referrer-when-downgrade'      => __('no-referrer-when-downgrade', 'pw-security-helpers'),
                                'same-origin'                     => __('same-origin', 'pw-security-helpers'),
                                'origin'                          => __('origin', 'pw-security-helpers'),
                                'origin-when-cross-origin'        => __('origin-when-cross-origin', 'pw-security-helpers'),
                                'strict-origin'                   => __('strict-origin', 'pw-security-helpers'),
                                'strict-origin-when-cross-origin' => __('strict-origin-when-cross-origin', 'pw-security-helpers'),
                                'unsafe-url'                      => __('unsafe-url', 'pw-security-helpers'),
                            ),
                        ),
                    ),
                ),
                'permissions_policy' => array(
                    'label'       => __('Permissions-Policy', 'pw-security-helpers'),
                    'description' => __('Decide which powerful browser features are allowed.', 'pw-security-helpers'),
                    'fields'      => array(
                        'value' => array(
                            'type'        => 'textarea',
                            'label'       => __('Policy', 'pw-security-helpers'),
                            'description' => __('Provide a Permissions-Policy directive string, e.g., geolocation=(), camera=()', 'pw-security-helpers'),
                        ),
                    ),
                ),
            );
        }

        /**
         * Block enumeration or dangerous endpoints based on configured options.
         */
        public function maybe_block_requests()
        {
            if (is_admin()) {
                return;
            }

            $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';

            if (!empty($this->options['block_user_endpoint'])) {
                if (false !== strpos($request_uri, '/wp-json/wp/v2/users')) {
                    $is_enumeration = false;

                    if (!empty($_GET['search'])) {
                        $is_enumeration = true;
                    }

                    if (!empty($_GET['context']) || !empty($_GET['roles']) || !empty($_GET['who'])) {
                        $is_enumeration = true;
                    }

                    if ($is_enumeration) {
                        wp_die(
                            __('Access to this REST endpoint is forbidden.', 'pw-security-helpers'),
                            __('Forbidden', 'pw-security-helpers'),
                            array('response' => 403)
                        );
                    }
                }
            }

            if (!empty($this->options['block_author_enum'])) {
                if (isset($_GET['author']) && '' !== $_GET['author']) {
                    $author_param = $_GET['author'];
                    if (is_numeric($author_param)) {
                        wp_die(
                            __('Author enumeration is disabled on this site.', 'pw-security-helpers'),
                            __('Forbidden', 'pw-security-helpers'),
                            array('response' => 403)
                        );
                    }
                }
            }
        }

        /**
         * Optionally restrict access to the REST API to authenticated users only.
         *
         * @param WP_Error|bool|null $result Existing auth results to honour.
         * @return WP_Error|bool|null
         */
        public function maybe_restrict_rest_api($result)
        {
            if (!empty($result)) {
                return $result;
            }

            if (function_exists('rest_is_request')) {
                if (!rest_is_request()) {
                    return $result;
                }
            } elseif (false === strpos($_SERVER['REQUEST_URI'], rest_get_url_prefix())) {
                return $result;
            }

            if (is_user_logged_in()) {
                return $result;
            }

            return new WP_Error(
                'rest_forbidden',
                __('The REST API on this site is restricted to authenticated users.', 'pw-security-helpers'),
                array('status' => 403)
            );
        }

        /**
         * Send the configured HTTP security headers when appropriate.
         */
        public function maybe_send_security_headers()
        {
            if (headers_sent()) {
                return;
            }

            $headers = $this->build_security_headers();

            foreach ($headers as $name => $value) {
                if ('' === $value) {
                    continue;
                }
                header($name . ': ' . $value, true);
            }
        }

        /**
         * Build the list of HTTP security headers based on the saved options.
         *
         * @return array
         */
        private function build_security_headers()
        {
            $headers = array();
            $options = isset($this->options['security_headers']) && is_array($this->options['security_headers']) ? $this->options['security_headers'] : array();

            foreach ($this->get_security_header_definitions() as $header_key => $definition) {
                $header_options = isset($options[$header_key]) && is_array($options[$header_key]) ? $options[$header_key] : array();

                if (empty($header_options['enabled'])) {
                    continue;
                }

                switch ($header_key) {
                    case 'hsts':
                        if (!is_ssl()) {
                            continue 2;
                        }

                        $max_age = isset($header_options['max_age']) ? absint($header_options['max_age']) : 0;
                        $value_parts = array('max-age=' . $max_age);

                        if (!empty($header_options['include_subdomains'])) {
                            $value_parts[] = 'includeSubDomains';
                        }

                        if (!empty($header_options['preload'])) {
                            $value_parts[] = 'preload';
                        }

                        $headers['Strict-Transport-Security'] = implode('; ', $value_parts);
                        break;

                    case 'content_security_policy':
                        $policy = isset($header_options['value']) ? trim($header_options['value']) : '';
                        if ('' !== $policy) {
                            $headers['Content-Security-Policy'] = $policy;
                        }
                        break;

                    case 'x_frame_options':
                        $value = isset($header_options['value']) ? trim($header_options['value']) : '';
                        if ('' !== $value) {
                            $headers['X-Frame-Options'] = $value;
                        }
                        break;

                    case 'x_content_type_options':
                        $headers['X-Content-Type-Options'] = 'nosniff';
                        break;

                    case 'referrer_policy':
                        $value = isset($header_options['value']) ? trim($header_options['value']) : '';
                        if ('' !== $value) {
                            $headers['Referrer-Policy'] = $value;
                        }
                        break;

                    case 'permissions_policy':
                        $value = isset($header_options['value']) ? trim($header_options['value']) : '';
                        if ('' !== $value) {
                            $headers['Permissions-Policy'] = $value;
                        }
                        break;
                }
            }

            return $headers;
        }

        /**
         * Add an entry to the Settings menu for our plugin.
         */
        public function add_settings_page()
        {
            add_options_page(
                __('PW Security Helpers', 'pw-security-helpers'),
                __('PW Security Helpers', 'pw-security-helpers'),
                'manage_options',
                'pw-security-helpers',
                array($this, 'render_settings_page')
            );
        }

        /**
         * Register our option and the fields that appear on the settings page.
         */
        public function register_settings()
        {
            register_setting(
                'pwsh_settings_group',
                $this->option_name,
                array($this, 'sanitize_options')
            );

            add_settings_section(
                'pwsh_main_section',
                __('Core Security Controls', 'pw-security-helpers'),
                function () {
                    echo '<p>' . esc_html__('Toggle the core protections below to harden common attack vectors.', 'pw-security-helpers') . '</p>';
                },
                'pw-security-helpers-core'
            );

            add_settings_field(
                'block_user_endpoint',
                __('Block REST API User Enumeration', 'pw-security-helpers'),
                array($this, 'render_checkbox_field'),
                'pw-security-helpers-core',
                'pwsh_main_section',
                array(
                    'label_for'   => 'block_user_endpoint',
                    'option_key'  => 'block_user_endpoint',
                    'description' => __('Stops access to the /wp-json/wp/v2/users endpoint when a search or filter parameter is supplied.', 'pw-security-helpers'),
                )
            );

            add_settings_field(
                'block_author_enum',
                __('Block Author Enumeration', 'pw-security-helpers'),
                array($this, 'render_checkbox_field'),
                'pw-security-helpers-core',
                'pwsh_main_section',
                array(
                    'label_for'   => 'block_author_enum',
                    'option_key'  => 'block_author_enum',
                    'description' => __('Prevents enumeration of author IDs via URLs such as /?author=1.', 'pw-security-helpers'),
                )
            );

            add_settings_field(
                'disable_xmlrpc',
                __('Disable XML-RPC', 'pw-security-helpers'),
                array($this, 'render_checkbox_field'),
                'pw-security-helpers-core',
                'pwsh_main_section',
                array(
                    'label_for'   => 'disable_xmlrpc',
                    'option_key'  => 'disable_xmlrpc',
                    'description' => __('Turns off the xmlrpc.php endpoint. This is rarely needed nowadays and disabling it can block some attack vectors.', 'pw-security-helpers'),
                )
            );

            add_settings_field(
                'restrict_rest_api',
                __('Restrict REST API to Authenticated Users', 'pw-security-helpers'),
                array($this, 'render_checkbox_field'),
                'pw-security-helpers-core',
                'pwsh_main_section',
                array(
                    'label_for'   => 'restrict_rest_api',
                    'option_key'  => 'restrict_rest_api',
                    'description' => __('When enabled, visitors must be logged in to access any REST API endpoint.', 'pw-security-helpers'),
                )
            );

            add_settings_section(
                'pwsh_headers_section',
                __('HTTP Security Headers', 'pw-security-helpers'),
                function () {
                    echo '<p>' . esc_html__('Enable and configure standard HTTP security headers. Adjust values to match your application needs before activating them.', 'pw-security-helpers') . '</p>';
                },
                'pw-security-helpers-headers'
            );

            foreach ($this->get_security_header_definitions() as $header_key => $definition) {
                add_settings_field(
                    'security_headers_' . $header_key,
                    $definition['label'],
                    array($this, 'render_security_header_field'),
                    'pw-security-helpers-headers',
                    'pwsh_headers_section',
                    array(
                        'header_key' => $header_key,
                        'definition' => $definition,
                    )
                );
            }
        }

        /**
         * Sanitize the options before saving.
         *
         * @param array $input Raw option values from the settings form.
         * @return array
         */
        public function sanitize_options($input)
        {
            $defaults = $this->get_default_options();
            $sanitized = $defaults;

            if (!is_array($input)) {
                return $sanitized;
            }

            $sanitized['block_user_endpoint'] = (!empty($input['block_user_endpoint']) && '1' === (string) $input['block_user_endpoint']) ? 1 : 0;
            $sanitized['block_author_enum'] = (!empty($input['block_author_enum']) && '1' === (string) $input['block_author_enum']) ? 1 : 0;
            $sanitized['disable_xmlrpc'] = (!empty($input['disable_xmlrpc']) && '1' === (string) $input['disable_xmlrpc']) ? 1 : 0;
            $sanitized['restrict_rest_api'] = (!empty($input['restrict_rest_api']) && '1' === (string) $input['restrict_rest_api']) ? 1 : 0;

            if (isset($input['security_headers']) && is_array($input['security_headers'])) {
                $sanitized['security_headers'] = $this->sanitize_security_headers($input['security_headers']);
            }

            return $sanitized;
        }

        /**
         * Sanitize the security header configuration.
         *
         * @param array $input Raw security header options.
         * @return array
         */
        private function sanitize_security_headers(array $input)
        {
            $definitions = $this->get_security_header_definitions();
            $defaults = $this->get_default_options();
            $defaults = $defaults['security_headers'];
            $sanitized = array();

            foreach ($definitions as $header_key => $definition) {
                $header_defaults = isset($defaults[$header_key]) ? $defaults[$header_key] : array('enabled' => 0);
                $incoming = isset($input[$header_key]) && is_array($input[$header_key]) ? $input[$header_key] : array();
                $sanitized[$header_key] = $this->sanitize_single_header($incoming, $header_defaults, $definition);
            }

            return $sanitized;
        }

        /**
         * Sanitize a single security header configuration.
         *
         * @param array $incoming Raw header values.
         * @param array $defaults Default header values.
         * @param array $definition Field metadata.
         * @return array
         */
        private function sanitize_single_header(array $incoming, array $defaults, array $definition)
        {
            $sanitized = $defaults;
            $sanitized['enabled'] = (!empty($incoming['enabled']) && '1' === (string) $incoming['enabled']) ? 1 : 0;

            foreach ($definition['fields'] as $field_key => $field_definition) {
                $field_type = isset($field_definition['type']) ? $field_definition['type'] : 'text';
                $raw_value = isset($incoming[$field_key]) ? $incoming[$field_key] : null;

                switch ($field_type) {
                    case 'checkbox':
                        $sanitized[$field_key] = (!empty($raw_value) && '1' === (string) $raw_value) ? 1 : 0;
                        break;

                    case 'number':
                        $sanitized[$field_key] = isset($raw_value) ? absint($raw_value) : $defaults[$field_key];
                        break;

                    case 'select':
                        $allowed = isset($field_definition['options']) && is_array($field_definition['options']) ? array_keys($field_definition['options']) : array();
                        $sanitized[$field_key] = (isset($raw_value) && in_array($raw_value, $allowed, true)) ? $raw_value : $defaults[$field_key];
                        break;

                    case 'textarea':
                        $sanitized[$field_key] = isset($raw_value) ? sanitize_textarea_field($raw_value) : $defaults[$field_key];
                        break;

                    default:
                        $sanitized[$field_key] = isset($raw_value) ? sanitize_text_field($raw_value) : $defaults[$field_key];
                        break;
                }
            }

            return $sanitized;
        }

        /**
         * Render a checkbox input field for basic toggles.
         *
         * @param array $args Arguments passed from add_settings_field.
         */
        public function render_checkbox_field($args)
        {
            $option_key = isset($args['option_key']) ? $args['option_key'] : '';
            if (!$option_key) {
                return;
            }

            $checked = !empty($this->options[$option_key]) ? 'checked' : '';
            echo '<input type="checkbox" id="' . esc_attr($option_key) . '" name="' . esc_attr($this->option_name) . '[' . esc_attr($option_key) . ']" value="1" ' . $checked . ' />';

            if (!empty($args['description'])) {
                echo '<p class="description">' . esc_html($args['description']) . '</p>';
            }
        }

        /**
         * Render a composite field for configuring an individual security header.
         *
         * @param array $args Arguments passed from add_settings_field.
         */
        public function render_security_header_field($args)
        {
            $header_key = isset($args['header_key']) ? $args['header_key'] : '';
            $definition = isset($args['definition']) ? $args['definition'] : array();

            if (!$header_key || empty($definition)) {
                return;
            }

            $defaults = $this->get_default_options();
            $defaults = isset($defaults['security_headers'][$header_key]) ? $defaults['security_headers'][$header_key] : array();
            $current_values = isset($this->options['security_headers'][$header_key]) && is_array($this->options['security_headers'][$header_key]) ? $this->options['security_headers'][$header_key] : array();
            $current_values = $this->merge_options($defaults, $current_values);

            $name_prefix = $this->option_name . '[security_headers][' . $header_key . ']';
            $enabled_id = 'pwsh_' . $header_key . '_enabled';

            echo '<fieldset>';
            echo '<label for="' . esc_attr($enabled_id) . '">';
            echo '<input type="checkbox" id="' . esc_attr($enabled_id) . '" name="' . esc_attr($name_prefix . '[enabled]') . '" value="1" ' . (!empty($current_values['enabled']) ? 'checked' : '') . ' />';
            echo ' ' . esc_html__('Enable header', 'pw-security-helpers');
            echo '</label>';

            if (!empty($definition['description'])) {
                echo '<p class="description">' . esc_html($definition['description']) . '</p>';
            }

            foreach ($definition['fields'] as $field_key => $field_definition) {
                $field_type = isset($field_definition['type']) ? $field_definition['type'] : 'text';
                $field_id = 'pwsh_' . $header_key . '_' . $field_key;
                $field_name = $name_prefix . '[' . $field_key . ']';
                $current_value = isset($current_values[$field_key]) ? $current_values[$field_key] : '';
                $field_label = isset($field_definition['label']) ? $field_definition['label'] : '';
                $field_classes = 'pwsh-field pwsh-field-' . $field_type;

                echo '<div class="' . esc_attr($field_classes) . '">';

                if ($field_label) {
                    echo '<label for="' . esc_attr($field_id) . '">' . esc_html($field_label) . '</label>';
                }

                switch ($field_type) {
                    case 'number':
                        $attributes = '';
                        if (!empty($field_definition['attributes']) && is_array($field_definition['attributes'])) {
                            foreach ($field_definition['attributes'] as $attr_key => $attr_value) {
                                $attributes .= ' ' . esc_attr($attr_key) . '="' . esc_attr($attr_value) . '"';
                            }
                        }
                        echo '<input type="number" id="' . esc_attr($field_id) . '" name="' . esc_attr($field_name) . '" value="' . esc_attr($current_value) . '"' . $attributes . ' />';
                        break;

                    case 'textarea':
                        echo '<textarea id="' . esc_attr($field_id) . '" name="' . esc_attr($field_name) . '" rows="4" cols="60">' . esc_textarea($current_value) . '</textarea>';
                        break;

                    case 'select':
                        echo '<select id="' . esc_attr($field_id) . '" name="' . esc_attr($field_name) . '">';
                        if (!empty($field_definition['options']) && is_array($field_definition['options'])) {
                            foreach ($field_definition['options'] as $option_value => $option_label) {
                                $selected = selected($current_value, $option_value, false);
                                echo '<option value="' . esc_attr($option_value) . '" ' . $selected . '>' . esc_html($option_label) . '</option>';
                            }
                        }
                        echo '</select>';
                        break;

                    case 'checkbox':
                        echo '<input type="checkbox" id="' . esc_attr($field_id) . '" name="' . esc_attr($field_name) . '" value="1" ' . (!empty($current_value) ? 'checked' : '') . ' />';
                        break;

                    default:
                        echo '<input type="text" id="' . esc_attr($field_id) . '" name="' . esc_attr($field_name) . '" value="' . esc_attr($current_value) . '" />';
                        break;
                }

                if (!empty($field_definition['description'])) {
                    echo '<p class="description">' . esc_html($field_definition['description']) . '</p>';
                }

                echo '</div>';
            }

            echo '</fieldset>';
        }

        /**
         * Render the settings page content with tabbed sections.
         */
        public function render_settings_page()
        {
            $active_tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'core';
            if (!in_array($active_tab, array('core', 'headers'), true)) {
                $active_tab = 'core';
            }

            $tabs = array(
                'core'    => __('Core Protections', 'pw-security-helpers'),
                'headers' => __('Security Headers', 'pw-security-helpers'),
            );

            $base_url = admin_url('options-general.php?page=pw-security-helpers');
            ?>
            <div class="wrap">
                <h1><?php echo esc_html__('PW Security Helpers', 'pw-security-helpers'); ?></h1>
                <h2 class="nav-tab-wrapper">
                    <?php foreach ($tabs as $tab_id => $label) : ?>
                        <?php
                        $class = 'nav-tab' . ($active_tab === $tab_id ? ' nav-tab-active' : '');
                        $tab_url = add_query_arg(array('tab' => $tab_id), $base_url);
                        ?>
                        <a href="<?php echo esc_url($tab_url); ?>" class="<?php echo esc_attr($class); ?>">
                            <?php echo esc_html($label); ?>
                        </a>
                    <?php endforeach; ?>
                </h2>
                <?php settings_errors(); ?>
                <form method="post" action="options.php">
                    <?php
                    settings_fields('pwsh_settings_group');

                    if ('headers' === $active_tab) {
                        do_settings_sections('pw-security-helpers-headers');
                    } else {
                        do_settings_sections('pw-security-helpers-core');
                    }

                    submit_button();
                    ?>
                </form>
            </div>
            <?php
        }
    }

    // Initialise our plugin so hooks register immediately.
    new PW_Security_Helpers();
}
