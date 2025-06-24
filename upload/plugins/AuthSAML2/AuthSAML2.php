<?php
/*
 * SAML Authentication plugin for LimeSurvey
 * Copyright (C) 2023 Sixto Pablo Martin Garcia <sixto.martin.garcia@gmail.com>
 */

require_once "_toolkit_loader.php";
require_once "auth_saml2_hooks.php";

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\IdPMetadataParser;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

define('SPMETADATAURL', Yii::app()->createUrl("/plugins/direct/plugin/AuthSAML2/function/samlmetadata"));
define('IDPMETADATAIMPORTERURL', Yii::app()->createUrl("/admin/pluginhelper/sa/fullpagewrapper/plugin/AuthSAML2/method/samlimportmetadata"));

class AuthSAML2 extends LimeSurvey\PluginManager\AuthPluginBase
{

    const ERROR_NO_IDP = 200;

    protected $storage = 'DbStorage';

    protected $samlAuth = null;

    static protected $description = 'SAML2 authentication plugin';
    static protected $name = 'SAML2';

    protected $settings = [
        'sp metadata' => [
            'type' => 'info',
            'label' => 'Service Provider Metadata:',
            'help' => 'Share with the IdP administrator the SP metadata, available as an XML at the <a target="_blank" href="'.SPMETADATAURL.'">SP SAML Metadata view</a>.<br>If you are using multiple IdPs, take in mind that each IdP registered will be related to its own SP so add to the SP Metadata URL <i><code>/idp/{idp_index}</code></i>'
        ],
        'idp_settings' => [
            'type' => 'info',
            'label' => 'Identity Provider settings:',
            'help' => 'This section may contain IdP data extracted from the IdP metadata XML.<br>
                    If you are registering multiple IdPs, you may use the <i>Multiple IdP support</i> field, each IdP will add <i><code>/idp/{idp_index}</code></i> in the discovery page.<br>
                    In order to import IdP XML Metadata, use the <a href="'.IDPMETADATAIMPORTERURL.'" >Importer IdP view</a>.'
        ],
        'idp_name' => [
            'type' => 'string',
            'label' => 'IdP Name',
            'default' => '',
            'help' => 'If you register more than 1 IdP, set a name to this IdP. That name will appear on the SAML Discovery page'
        ],
        'idp_entityid' => [
            'type' => 'string',
            'label' => 'IdP EntityID',
            'default' => '',
        ],
        'idp_sso_url' => [
            'type' => 'string',
            'label' => 'IdP SSO URL',
            'default' => '',
        ],
        'idp_slo_url' => [
            'type' => 'string',
            'label' => 'IdP SLO URL',
            'default' => '',
        ],
        'idp_x509cert' => [
            'type' => 'text',
            'label' => 'IdP x509cert',
            'value' => '<textarea name="idp_x509cert"></textarea>',
        ],
        'idp_x509cert_2' => [
            'type' => 'text',
            'label' => 'Alternative IdP x509cert',
            'value' => '<textarea name="idp_x509cert_2"></textarea>',
            'help' => 'Optional x509cert that can be registered. Usefull during certificate migration'
        ],
        'idp_x509cert_3' => [
            'type' => 'text',
            'label' => 'Another alternative IdP x509cert',
            'value' => '<textarea name="idp_x509cert_3"></textarea>',
            'help' => 'Another optional x509cert.'
        ],
        'idp_multi_support' => [
            'type' => 'json',
            'editorOptions'=> ['mode'=>'text'],
            'label' => 'Multiple IdP support',
            'value' => '<textarea name="idp_multi_support"></textarea>',
            'help' => 'If you plan to support more than 1 IdPs place here the IdP info in json format: Each IdP data should contain name, ssourl, slourl, cert, cert2 and cert3. Use an ID as the index for each IdP object.'
        ],
        'idp_discovery_method' => [
            'type' => 'select',
            'label' => 'IdP Discovery method',
            'options' => [
                'idp_name' => 'IdP name',
                'idp_entityid' => 'IdP Entity Id',
                'custom' => 'Custom'
            ],
            'default' => 'idp_name',
            'help'=>'If you are using multiple IdPs in the LimeSurvey instance, select the IdP Discovery method to be used.',
        ],
        'simplesamlphp_mappings' => [
            'type' => 'info',
            'label' => 'Mappings:',
            'help' => 'Sometimes, the names of the attributes sent by the IdP do not match those used by LimeSurvey for the customer accounts. In this section, we must set the mapping between IdP fields and LimeSurvey fields. You can set different possible mappings for each attribute that gonna be mapped, comma-separating them. Order matters: if there is a saml attribute that matches is retrieved, no other mappings are considered for that attribute. If you have multiple IdPs registered, add all the possible mappings for each attribute.'
        ],
        'saml_uid_mapping' => [
            'type' => 'string',
            'label' => 'SAML attribute used as username, you can add multiple possible mappings adding the values comma-separated.',
            'default' => 'uid',
        ],
        'saml_mail_mapping' => [
            'type' => 'string',
            'label' => 'SAML attribute used as email, you can add multiple possible mappings the values comma-separated.',
            'default' => 'mail',
        ],
        'saml_name_mapping' => [
            'type' => 'string',
            'label' => 'SAML attribute used as fullname, you can add multiple possible mappings the values comma-separated.',
            'default' => 'cn',
        ],
        'saml_group_mapping' => [
            'type' => 'string',
            'label' => 'SAML attribute that contains Group info, you can add multiple possible mappings adding the values comma-separated.'
        ],
        'saml_lang_mapping' => [
            'type' => 'string',
            'label' => 'SAML attribute that contains Lang info, you can add multiple possible mappings adding the values comma-separated.'
        ],
        'saml_options' => [
            'type' => 'info',
            'label' => 'Options:',
        ],
        'authtype_base' => [
            'type' => 'string',
            'label' => 'Authtype base',
            'default' => 'Authdb',
            'help' => 'The default Auth mechanism enabled and loaded on the login view'
        ],
        'storage_base' => [
            'type' => 'string',
            'label' => 'Storage base',
            'default' => 'DbStorage',
        ],
        'auto_create_users' => [
            'type' => 'checkbox',
            'label' => 'Auto create users',
            'default' => true,
            'help' => 'If a user does not exists and this flag is enabled, the plugin will be able to create a new user at LimeSurvey with the data provided by the IdP'
        ],
        'auto_update_users' => [
            'type' => 'checkbox',
            'label' => 'Auto update users',
            'default' => true,
            'help' => 'If enabled, the plugin will update at Limesurvey the name, email and lang of the user, during the sso process '
        ],
        'auto_create_group' => [
            'type' => 'checkbox',
            'label' => 'Auto create groups',
            'default' => false,
            'help' => "Enable it in order to allow the plugin to create new groups provided by the IdP that don't exists on LimeSurvey"
        ],
        'sync_group' => [
            'type' => 'checkbox',
            'label' => 'Sync group info',
            'default' => false,
            'help' => 'Enable it in order to sync user groups. User will have the groups provided by the IdP. Old assigned groups will be removed.'
        ],
        'alternative_forgot_pw_url' => [
            'type' => 'string',
            'label' => 'Alternative Forgot PW URL',
            'default' => '',
            'help' => 'Set an alternative url if your password are stored externaly'
        ],
        'disable_slo' => [
            'type' => 'checkbox',
            'label' => 'Disable SLO',
            'default' => false,
            'help' => 'Mark this flag in order to disable Single Logout. SLO  is a complex functionality, the most common SLO implementation is based on front-channel (redirections), sometimes if the SLO workflow fails a user can be blocked in an unhandled view. If the admin does not control the set of apps involved in the SLO process, you may want to disable this functionality to avoid more problems than benefits.'
        ],
        'force_saml_login' => [
            'type' => 'checkbox',
            'label' => 'Force SAML login',
            'help' => 'Enable it in order to force all users to login only with SAML. When user access the login view, the SSO process will be automatically executed'
        ],
        'bypass_force_saml_login' => [
            'type' => 'checkbox',
            'label' => 'Allow Bypass Force SAML login',
            'default' => true,
            'help' => 'Enable it in order to allow the admin to bypass the Force SAML feature by adding the "normal" GET parameter to the URL. Ex. index.php/admin/authentication/sa/login?normal'
        ],
        'prevent_saml_users_normal_login' => [
            'type' => 'checkbox',
            'label' => 'Prevent users created by the plugin use normal login',
            'default' => false,
            'help' => 'Enable it in order to block normal login for users generated by the plugin'
        ],
        'saml_login_text' => [
            'type' => 'string',
            'label' => 'Text for the SAML link',
            'default' => 'SAML Login',
        ],
        'saml_login_text_position' => [
            'type' => 'select',
            'label' => 'Position of the SAML link',
            'options' => ["top" => "Top", "bottom" => "Bottom"],
            'default' => "top",
            'help' => 'Decide where to place the SAML link at the login view'
        ],
        'auto_create_global_permissions' => [
            'type' => 'info',
            'label' => 'Global Permissions to be assigned to the provisioned user:',
            'help' => 'In this section we can define the default permission that will be assigned to new users. Later can be modified by the auth_saml2_hook_extend_permissions hook.'
        ],
        'entity_permission' => [
            'type' => 'string',
            'label' => 'Entity permission (leave as global)',
            'default' => 'global',
        ],
        'entity_id_permission' => [
            'type' => 'string',
            'label' => 'Entity ID permission (leave as 0)',
            'default' => '0',
        ],
        'auto_create_permission_participant_panel' => [
            'type' => 'checkbox',
            'label' => 'Central participant database',
            'default' => false,
            'help' => 'Permission to create participants in the central participants database (for which all permissions are automatically given) and view, update and delete participants from other users'
        ],
        'auto_create_permission_labelsets' => [
            'type' => 'checkbox',
            'label' => 'Label sets',
            'default' => false,
            'help' => 'Permission to create, view, update, delete, export and import label sets/labels'
        ],
        'auto_create_permission_settings_plugins' => [
            'type' => 'checkbox',
            'label' => 'Settings & Plugins',
            'default' => false,
            'help' => 'Permission to view and update global settings & plugins and to delete and import plugins'
        ],
        'auto_create_permission_surveys' => [
            'type' => 'checkbox',
            'label' => 'Surveys',
            'default' => true,
            'help' => 'Permission to create surveys (for which all permissions are automatically given) and view, update and delete surveys from other users'
        ],
        'auto_create_permission_templates' => [
            'type' => 'checkbox',
            'label' => 'Templates',
            'default' => false,
            'help' => 'Permission to create, view, update, delete, export and import templates'
        ],
        'auto_create_permission_user_groups' => [
            'type' => 'checkbox',
            'label' => 'User groups',
            'default' => false,
            'help' => 'Permission to create, view, update and delete user groups'
        ],
        'auto_create_permission_users' => [
            'type' => 'checkbox',
            'label' => 'Users',
            'default' => false,
            'help' => 'Permission to create, view, update and delete users'
        ],
        'auto_create_permission_superadministrator' => [
            'type' => 'checkbox',
            'label' => 'Superadministrator',
            'default' => false,
            'help' => 'Unlimited administration permissions'
        ],
        'auto_create_permission_auth_db' => [
            'type' => 'checkbox',
            'label' => 'Use internal database authentication',
            'default' => false,
            'help' => 'Allow user to authenticate using internal database authentication'
        ],
        'advanced_saml_settings' => [
            'type' => 'info',
            'label' => 'Advanced SAML Settings:',
        ],
        'debug' => [
            'type' => 'checkbox',
            'label' => 'Debug Mode',
            'default' => false,
            'help' => 'Enable for debugging the SAML workflow. Errors and Warnigs will be shown.'
        ],
        'nameid_encrypted' => [
            'type' => 'checkbox',
            'label' => 'Encrypt nameID',
            'default' => false,
            'help' => 'The nameID sent by this SP will be encrypted.'
        ],
        'signmetadata' => [
            'type' => 'checkbox',
            'label' => 'Sign metadata',
            'default' => false,
            'help' => 'The SP metadata gonna be signed.'
        ],
        'authn_request_signed' => [
            'type' => 'checkbox',
            'label' => 'Sign AuthnRequest',
            'default' => false,
            'help' => 'The samlp:AuthnRequest messages sent by this SP will be signed.'
        ],
        'logout_request_signed' => [
            'type' => 'checkbox',
            'label' => 'Sign LogoutRequest',
            'default' => false,
            'help' => 'The samlp:logoutRequest messages sent by this SP will be signed.'
        ],
        'logout_response_signed' => [
            'type' => 'checkbox',
            'label' => 'Sign LogoutResponse',
            'default' => false,
            'help' => 'The samlp:logoutResponse messages sent by this SP will be signed.'
        ],
        'want_message_signed' => [
            'type' => 'checkbox',
            'label' => 'Reject Unsigned Messages',
            'default' => false,
            'help' => 'Reject unsigned samlp:Response, samlp:LogoutRequest and samlp:LogoutResponse received'
        ],
        'want_assertion_signed' => [
            'type' => 'checkbox',
            'label' => 'Reject Unsigned Assertions',
            'default' => false,
            'help' => 'Reject unsigned saml:Assertion received'
        ],
        'want_assertion_encrypted' => [
            'type' => 'checkbox',
            'label' => 'Reject Unencrypted Assertions',
            'default' => false,
            'help' => 'Reject unencrypted saml:Assertion received'
        ],
        'sp_entityid' => [
            'type' => 'string',
            'label' => 'SP EntityID',
            'default' => '',
        ],
        'nameidformat' => [
            'type' => 'select',
            'label' => 'NameIDFormat',
            'options' => [
                Constants::NAMEID_UNSPECIFIED => Constants::NAMEID_UNSPECIFIED,
                Constants::NAMEID_EMAIL_ADDRESS => Constants::NAMEID_EMAIL_ADDRESS,
                Constants::NAMEID_TRANSIENT => Constants::NAMEID_TRANSIENT,
                Constants::NAMEID_PERSISTENT => Constants::NAMEID_PERSISTENT,
                Constants::NAMEID_ENTITY => Constants::NAMEID_ENTITY,
                Constants::NAMEID_ENCRYPTED => Constants::NAMEID_ENCRYPTED,
                Constants::NAMEID_KERBEROS => Constants::NAMEID_KERBEROS,
                Constants::NAMEID_X509_SUBJECT_NAME => Constants::NAMEID_X509_SUBJECT_NAME,
                Constants::NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME => Constants::NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME
            ],
            'default' => null,
            'help' => 'Specifies constraints on the name identifier to be used to represent the requested subject.'
        ],
        'requestedauthncontext' => [
            'type' => 'select',
            'label' => 'Requested AuthN Context',
            'options' => [
                'unspecified' => Constants::AC_UNSPECIFIED,
                'password' => Constants::AC_PASSWORD,
                'passwordprotectedtransport' => Constants::AC_PASSWORD_PROTECTED,
                'x509' => Constants::AC_X509,
                'smartcard' => Constants::AC_SMARTCARD,
                'kerberos' => Constants::AC_KERBEROS
            ],
            'default' => null,
            'htmlOptions' => ['multiple' => 'multiple'],
            'help'=>'AuthContext sent in the AuthNRequest. You can select none, one or multiple values.',
        ],
        'lowercase_url_encoding' => [
            'type' => 'checkbox',
            'label' => 'Lowercase URL encoding?',
            'default' => false,
            'help'=>'Some IdPs like ADFS can use lowercase URL encoding, but the plugin expects uppercase URL encoding, enable it to fix incompatibility issues.'
        ],
        'retrieve_parameters_from_server' => [
            'type' => 'checkbox',
            'label' => 'Retrieve Parameters From Server',
            'default' => false,
            'help' => 'Sometimes when the app is behind a firewall or proxy, the query parameters can be modified an this affects the signature validation process on HTTP-Redirectbinding. Active this if you are seeing signature validation failures. The plugin will try to extract the original query parameters.'
        ],
        'sp_x509cert' => [
            'type' => 'html',
            'label' => 'SP x509cert',
            'value' => '<textarea name="sp_x509cert"></textarea>',
            'help' => 'Public Cert of the Service Provider. Used to encrypt.'
        ],
        'sp_privatekey' => [
            'type' => 'html',
            'label' => 'SP Private Key',
            'value' => '<textarea name="sp_privatekey"></textarea>',
            'help' => 'Private Key of the Service Provider. Used to sign or decrypt.'
        ],
        'signaturealgorithm' => [
            'type' => 'select',
            'label' => 'Signature Algorithm',
            'options' => [
                XMLSecurityKey::RSA_SHA1 => XMLSecurityKey::RSA_SHA1,
                XMLSecurityKey::RSA_SHA256 => XMLSecurityKey::RSA_SHA256,
                XMLSecurityKey::RSA_SHA384 => XMLSecurityKey::RSA_SHA384,
                XMLSecurityKey::RSA_SHA512 => XMLSecurityKey::RSA_SHA512
            ],
            'default' => null,
            'help'=>'Algorithm that will be used on signing process.',
        ],
        'digestalgorithm' => [
            'type' => 'select',
            'label' => 'Digest Algorithm',
            'options' => [
                XMLSecurityDSig::SHA1 => XMLSecurityDSig::SHA1,
                XMLSecurityDSig::SHA256 => XMLSecurityDSig::SHA256,
                XMLSecurityDSig::SHA384 => XMLSecurityDSig::SHA384,
                XMLSecurityDSig::SHA512 => XMLSecurityDSig::SHA512
            ],
            'default' => null,
            'help'=>'Algorithm that will be used on digest process.',
        ],
    ];

    protected $attributes = null;

    public function init()
    {
        /* Show page */
        $this->subscribe('newUnsecureRequest');
        $this->subscribe('newDirectRequest');

        $this->subscribe('beforeActivate');
        $this->subscribe('getGlobalBasePermissions');
        $this->subscribe('beforeLogin');

        $this->subscribe('newUserSession');

        if (!$this->get('disable_slo', null, null, false)) {
            $this->subscribe('beforeLogout');
        }

        if (!$this->get('force_saml_login', null, null, false)) {
            $this->subscribe('newLoginForm');
        }
    }

    public function newUnsecureRequest()
    {
        $event = $this->getEvent();

        if ($event->get('target') == 'AuthSAML2') {
            $function = $event->get('function');
            switch ($function) {
                case "samlacs":
                    $this->samlacs();
                    break;
                default:
                    break;
            }
        }
    }

    public function newDirectRequest()
    {
        $event = $this->getEvent();
        if ($event->get('target') == 'AuthSAML2') {
            $function = $event->get('function');
            switch ($function) {
                case "samlmetadata":
                    $this->samlmetadata(true);
                    break;
/*
    // Requires the addition at config/config.php of:

        'request' => array(
            'enableCsrfValidation' => true,
            'noCsrfValidationRoutes'=>array(
                'plugins/direct/plugin/AuthSAML2/function/samlacs',
            ),
        ),

                case "samlacs":
                    $this->samlacs();
*/
                default:
                    break;
            }
        }
    }

    public function samlmetadata($unsecure = false)
    {
        $idp = null;
        if (isset($_GET['idp'])) {
            $idp = $_GET['idp'];
        }
        $samlSettingsInfo = $this->getSettings($idp);
        $settings = new Settings($samlSettingsInfo, true);
        $metadata = $settings->getSPMetadata();
        $errors = $settings->validateMetadata($metadata);

        if (!empty($errors)) {
            $this->log("Invalid SP metadata:".implode(', ', $errors), \CLogger::LEVEL_ERROR);
        }

        if ($unsecure) {
            if (empty($errors)) {
                header('Content-Type: text/xml');
                echo $metadata;
                exit();
            } else {
                echo '<div class="row text-left">
                        <div class="col-lg-9 col-sm-9  ">
                            <b>Invalid SP metadata:</b> '.implode(', ', $errors).
                       '</div>
                      </div>';
            }
        } else {
            $this->renderPartial(
                'metadata',
                [
                    'metadata' => $metadata,
                    'errors' => $errors
                ],
                true
            );
        }
    }

    public function samlimportmetadata()
    {
        if (!Permission::model()->hasGlobalPermission('settings', 'update')) {
            Yii::app()->user->setFlash('error', gT("No permission"));
            $this->log("User ID ".Yii::app()->user->id.". No Permission to import metadata", \CLogger::LEVEL_ERROR);
            App()->controller->redirect(Yii::app()->createUrl('/admin'));
        }

        $error = null;
        if (Yii::app()->request->getIsPostRequest()) {
            $close = Yii::app()->request->getPost('close');
            if (!empty($close)) {
                return App()->controller->redirect(array('/admin/pluginmanager/sa/configure/id/'.$this->id));
            }

            if (!empty(Yii::app()->request->getPost('metadataxml'))) {
                Yii::app()->request->validateCsrfToken($this->getEvent());

                $mode = Yii::app()->request->getPost('mode');
                $xml = Yii::app()->request->getPost('metadataxml');

                try {
                    $metadata = @IdPMetadataParser::parseXML($xml);
                    if (!empty($metadata) && !empty($metadata['idp'])) {
                        $entityid = $sso = $slo = $cert = "";
                        if (isset($metadata['idp']['entityId']) && !empty($metadata['idp']['entityId'])) {
                            $entityid = $metadata['idp']['entityId'];
                        }
                        if (isset($metadata['idp']['singleSignOnService']) && !empty($metadata['idp']['singleSignOnService']['url'])) {
                            $sso = $metadata['idp']['singleSignOnService']['url'];
                        }
                        if (isset($metadata['idp']['singleSignOnService']) && !empty($metadata['idp']['singleLogoutService']['url'])) {
                            $slo = $metadata['idp']['singleLogoutService']['url'];
                        }
                        if (isset($metadata['idp']['x509cert']) && !empty($metadata['idp']['x509cert'])) {
                            $x509cert = $metadata['idp']['x509cert'];
                        }

                        if (!empty($entityid) && !empty($x509cert)) {
                            if ($mode == "default") {
                                $this->set('idp_entityid', $entityid);
                                $this->set('idp_sso_url', $sso);
                                $this->set('idp_slo_url', $slo);
                                $this->set('idp_x509cert', $x509cert);
                                $this->set('idp_x509cert_2', "");
                                $this->set('idp_x509cert_3', "");
                            } else {
                                $newIdPData = [
                                    "name" => "Imported IdP",
                                    "entityid" => $entityid,
                                    "ssourl" => $sso,
                                    "ssourl" => $slo,
                                    "cert" => $x509cert
                                ];

                                $IdPMultiSupportInfo = $this->getIdPMultiSupportInfo();
                                $extractedIdPData = null;

                                if (!empty($IdPMultiSupportInfo)) {
                                    $foundKey = null;
                                    $IdPsData = json_decode($IdPMultiSupportInfo, true);
                                    foreach ($IdPsData as $key => $idpData) {
                                        if ($idpData['entityid'] == $entityid) {
                                            $foundKey = $key;
                                            break;
                                        }
                                    }

                                    if ($foundKey != null) {
                                        $IdPsData[$foundKey] = $newIdPData;
                                    } else {
                                        $IdPsData[] = $newIdPData;
                                    }
                                } else {
                                    $IdPsData = [];
                                    $IdPsData[1] = $newIdPData;
                                }
                                $this->set('idp_multi_support', json_encode($IdPsData));
                            }
                            Yii::app()->user->setFlash('success', "Metadata saved!");
                            $save = Yii::app()->request->getPost('save');
                            if (!empty($save)) {
                                return App()->controller->redirect(array('/admin/pluginmanager/sa/configure/id/'.$this->id));
                            }
                        }
                    }
                } catch (\Exception $e) {
                    $this->log("SAML Importer: Invalid xml metadata", \CLogger::LEVEL_ERROR);
                    $error = gT("Invalid xml metadata");
                }
            }
        }

        return $this->renderPartial(
            'importmetadata',
            ["error" => $error],
            true
        );
    }

    public function samlacs()
    {
        $idp = null;
        if (isset($_GET['idp'])) {
            $idp = $_GET['idp'];
        }

        $samlAuth = $this->getSamlInstance($idp);
        $samlAuth->processResponse();
        if ($samlAuth->isAuthenticated()) {
            $_SESSION['samluser'] = $samlAuth->getAttributes();
            $_SESSION['samluser']['idp'] = $idp;
            $_SESSION['samluser']['NameId'] = array();
            $_SESSION['samluser']['NameId']['Value'] = $samlAuth->getNameId();
            $_SESSION['samluser']['NameId']['Format'] = $samlAuth->getNameIdFormat();
            $_SESSION['samluser']['NameId']['NameQualifier'] = $samlAuth->getNameIdNameQualifier();
            $_SESSION['samluser']['NameId']['SPNameQualifier'] = $samlAuth->getNameIdSPNameQualifier();
            $_SESSION['samluser']['NameId']['SessionIndex'] = $samlAuth->getSessionIndex();
            return App()->controller->redirect(array('/admin/authentication'));
        } else {
            $errors = $samlAuth->getErrors();
            if (!empty($errors)) {
              $this->log("SAML ACS Error:".implode(', ', $errors), \CLogger::LEVEL_ERROR);
              print_r($errors);
              $debug = $this->get('debug', null, null, true);
              if ($debug) {
                  $reason = $samlAuth->getLastErrorReason();
                  $this->log("SAML ACS Error:".$reason, \CLogger::LEVEL_DEBUG);
                  print_r($reason);
              }

            }
            echo "Not authenticated";
            exit();
        }
    }

    public function samlsls()
    {
        $idp = null;
        if (isset($_GET['idp'])) {
            $idp = $_GET['idp'];
        }

        $samlAuth = $this->getSamlInstance($idp);
        $retrieveParametersFromServer = $this->get('retrieve_parameters_from_server', null, null, false);
        $samlAuth->processSLO(false, null, $retrieveParametersFromServer);
        $errors = $samlAuth->getErrors();
        if (!empty($errors)) {
            $this->log("SAML SLS Error:".implode(', ', $errors), \CLogger::LEVEL_ERROR);
            echo '<p>' . implode(', ', $errors) . '</p>';
            $debug = $this->get('debug', null, null, true);
            if ($debug) {
                $reason = $samlAuth->getLastErrorReason();
                $this->log("SAML SLS Error:".$reason, \CLogger::LEVEL_DEBUG);
                print_r($reason);
            }
            exit();
        }
        return App()->controller->redirect(array('/admin/authentication'));
    }

    protected function getSamlInstance($id = null)
    {
        if ($this->samlAuth == null) {
            $this->samlSettingsInfo = $this->getSettings($id);
            $this->samlAuth = new Auth($this->samlSettingsInfo);
        }
        return $this->samlAuth;
    }

    protected function getSettings($id = null)
    {
        $spEntityId = $this->get('sp_entityid', null, null, '');
        if (empty($spEntityId)) {
            $spEntityId = $this->api->createUrl('plugins/direct/plugin/AuthSAML2/function/samlmetadata', []);
        }

        if (empty($id)) {
            $idstr = '';
            $idpData = [
                'entityId' => $this->get('idp_entityid', null, null, ''),
                'singleSignOnService' => [
                    'url' => $this->get('idp_sso_url', null, null, ''),
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                ],
                'singleLogoutService' => [
                    'url' => $this->get('idp_slo_url', null, null, ''),
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                ]
            ];
        } else {
            $idstr = '/idp/'.$id;
            $IdPMultiSupportInfo = $this->getIdPMultiSupportInfo();
            $extractedIdPData = null;
            if (!empty($IdPMultiSupportInfo)) {
                $IdPsData = json_decode($IdPMultiSupportInfo, true);
                if (!empty($IdPsData) && is_array($IdPsData) && isset($IdPsData[$id])) {
                    $extractedIdPData = $IdPsData[$id];
                }
            }

            if (empty($extractedIdPData)) {
                $this->log("SAML Login Error: No IdP Data", \CLogger::LEVEL_ERROR);
                $this->showError(self::ERROR_NO_IDP, gT("Data for IdP ".htmlentities($id)." not found"));
            }

            $idpData = [
                'entityId' => $extractedIdPData['entityid'],
                'singleSignOnService' => [
                    'url' => $extractedIdPData['ssourl'],
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                ]
            ];
            if (isset($extractedIdPData['slourl']) && !empty($extractedIdPData['slourl'])) {
                $idpData['singleLogoutService'] = [
                    'url' => $extractedIdPData['slourl'],
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                ];
            }
        }

        $settings = [
            'strict' => true,
            'debug' => $this->get('debug', null, null, true),
            'sp' => [
                'entityId' => $spEntityId,
                'assertionConsumerService' => [
                    'url' =>                     $this->api->createUrl('plugins/unsecure/plugin/AuthSAML2/function/samlacs'.$idstr, []),

//                    $this->api->createUrl('plugins/direct/plugin/AuthSAML2/function/samlacs', []),
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                ],
                'NameIDFormat' => $this->get('nameidformat', null, null, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'),
                'x509cert' => $this->cleanCert($this->get('sp_x509cert', null, null, '')),
                'privateKey' => $this->cleanCert($this->get('sp_privatekey', null, null, '')),
            ],
            'idp' => $idpData,
            'security' => [
                'signMetadata' => $this->get('signmetadata', null, null, false),
                'nameIdEncrypted' => $this->get('nameid_encrypted', null, null, false),
                'authnRequestsSigned' => $this->get('authn_request_signed', null, null, false),
                'logoutRequestSigned' => $this->get('logout_request_signed', null, null, false),
                'logoutResponseSigned' => $this->get('logout_response_signed', null, null, false),
                'wantMessagesSigned' => $this->get('want_message_signed', null, null, false),
                'wantAssertionsSigned' => $this->get('want_assertion_signed', null, null, false),
                'wantAssertionsEncrypted' => $this->get('want_assertion_encrypted', null, null, false),
                'wantNameId' => false,
                'requestedAuthnContext' => $this->get('requestedauthncontext', null, null, false),
                'relaxDestinationValidation' => true,
                'lowercaseUrlencoding' => $this->get('lowercase_url_encoding', null, null, false),
                'signatureAlgorithm' => $this->get('signaturealgorithm', null, null, 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'),
                'digestAlgorithm' => $this->get('digestalgorithm', null, null, 'http://www.w3.org/2000/09/xmldsig#sha1')
            ]
        ];

        if (empty($id)) {
            $idpX509cert = $this->cleanCert($this->get('idp_x509cert', null, null, ''));
            $idpX509cert2 = $this->cleanCert($this->get('idp_x509cert_2', null, null, ''));
            $idpX509cert3 = $this->cleanCert($this->get('idp_x509cert_3', null, null, ''));
        } else {
            $idpX509cert = isset($extractedIdPData['cert']) ? $extractedIdPData['cert'] : '';
            $idpX509cert2 = isset($extractedIdPData['cert2']) ? $extractedIdPData['cert2'] : '';
            $idpX509cert3 = isset($extractedIdPData['cert3']) ? $extractedIdPData['cert3'] : '';
        }

        $settings['idp']['x509certMulti'] = [
              'signing' => [
                  0 => $idpX509cert,
              ],
              'encryption' => [
                  0 => $idpX509cert,
              ]
        ];
        if (!empty($idpX509cert2)) {
            $settings['idp']['x509certMulti']['signing'][] = $idpX509cert2;
        }
        if (!empty($idpX509cert3)) {
            $settings['idp']['x509certMulti']['signing'][] = $idpX509cert3;
        }


        if (!$this->get('disable_slo', null, null, false)) {
            $settings['sp']['singleLogoutService'] = [
                'url' => $this->api->createUrl('admin/pluginhelper/sa/fullpagewrapper/plugin/AuthSAML2/method/samlsls'.$idstr, []),
                'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            ];
        }

        return $settings;
    }

    /**
     * Add AuthSAML Permission to global Permission
     * @return void
     */
    public function getGlobalBasePermissions()
    {
        $this->getEvent()->append('globalBasePermissions', [
            'auth_saml2' => [
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => gT("Use SAML2 authentication"),
                'description' => gT("Use SAML2 authentication"),
                'img' => 'usergroup'
            ],
        ]);
    }

    /**
     * Check availability of SAML Settings
     *
     * @return void
     */
    public function beforeActivate()
    {
        try {
            $this->getSamlInstance();
        } catch (Exception $e) {
            $event = $this->getEvent();
            $event->set('success', false);
            $errorMsg = str_replace('Invalid array settings', 'Invalid settings', $e->getMessage());
            $this->log("SAML2 Auth Plugin can't be activated. Invalid Settings", \CLogger::LEVEL_ERROR);
            $event->set('message', gT("SAML2 Auth Plugin can't be activated, the php-saml library raised an exception. ".$errorMsg));
            return;
        }

        $sqlQuery = "CREATE TABLE IF NOT EXISTS saml_users (userid integer NOT NULL)";
        $sqlCommand = Yii::app()->db->createCommand($sqlQuery);
        $sqlCommand->execute();
    }

    public function beforeLogin()
    {
        $idp = null;
        if (isset($_GET['idp'])) {
            $idp = $_GET['idp'];
        }

        if (isset($_GET['action'])) {
            if ($_GET['action'] == 'samlsso') {
                $samlAuth = $this->getSamlInstance($idp);
                $samlAuth->login();
            } else if ($_GET['action'] == 'samldiscovery') {
                $this->discoveryPage();
            }
        }
        if (empty($_POST) || (!isset($_POST['user']) && !isset($_POST['password']))) {
            if (isset($_SESSION['samluser'])) {
                $this->setAuthPlugin();
                $this->newUserSession();
            } else if ($this->get('force_saml_login', null, null, false)) {
                $bypass_force_saml_login = $this->get('bypass_force_saml_login', null, null, true);
                if (!$bypass_force_saml_login || (!isset($_GET['normal']) && empty($_POST))) {
                    $IdPMultiSupportInfo = $this->getIdPMultiSupportInfo();
                    if (empty($IdPMultiSupportInfo)) {
                        $samlAuth = $this->getSamlInstance();
                        $samlAuth->login();
                    } else {
                        return App()->controller->redirect(array('/admin/authentication/sa/login?action=samldiscovery'));
                    }
                }
            }
        } else if ($this->get('prevent_saml_users_normal_login', null, null, false)) {
            $oUser = $this->api->getUserByName($_POST['user']);
            if (!is_null($oUser)) {
                $uid = $oUser->uid;
                $result = Yii::app()->db->createCommand()->select('userid')->from('saml_users')->where('userid = :userid')->bindParam(":userid", $uid, PDO::PARAM_INT)->query();
                if (count($result) > 0) {
                    $this->log("SAML User not authorized to execute normal login. ".$uid, \CLogger::LEVEL_ERROR);
                    $this->showError(self::ERROR_UNKNOWN_IDENTITY, gT("SAML User not authorized to execute normal login"));
                }
            }
        }
    }

    public function showError($errorCode, $errorMessage)
    {
        $data = [
            'errormsg' => '', // We can add $errorCode here
            'maxattempts' => '',
            'sMessage' => $errorMessage
        ];

        $oAdminController = new AdminController('admin');
        $oAdminController->render("/admin/authentication/error", $data, false);
        exit();
    }

    public function beforeLogout()
    {
        if (isset($_SESSION['samluser'])) {
            $samlAuth = $this->getSamlInstance($_SESSION['samluser']['idp']);
            if (empty($samlAuth->getSLOurl())) {
                return;
            }

            $nameId = $sessionIndex = $nameIdFormat = $nameIdNameQualifier = $nameIdSPNameQualifier = null;

            if (isset($_SESSION['samluser']['NameId'])) {
                if (isset($_SESSION['samluser']['NameId']['Value'])) {
                    $nameId = $_SESSION['samluser']['NameId']['Value'];
                }
                if (isset($_SESSION['samluser']['NameId']['Format'])) {
                    $nameIdFormat = $_SESSION['samluser']['NameId']['Format'];
                }
                if (isset($_SESSION['samluser']['NameId']['NameQualifier'])) {
                    $nameIdNameQualifier = $_SESSION['samluser']['NameId']['NameQualifier'];
                }
                if (isset($_SESSION['samluser']['NameId']['SPNameQualifier'])) {
                    $nameIdSPNameQualifier = $_SESSION['samluser']['NameId']['SPNameQualifier'];
                }
                if (isset($_SESSION['samluser']['NameId']['SessionIndex'])) {
                    $sessionIndex = $_SESSION['samluser']['NameId']['SessionIndex'];
                }
            }
            $samlAuth->logout(null, [], $nameId, $sessionIndex, false, $nameIdFormat, $nameIdNameQualifier, $nameIdSPNameQualifier);
        }
    }

    public function newLoginForm()
    {
        $authtype_base = $this->get('authtype_base', null, null, 'Authdb');
        $IdPMultiSupportInfo = $this->getIdPMultiSupportInfo();
        $baseLoginUrl = $this->api->createUrl('admin/authentication/sa/login', []);
        if (strpos($baseLoginUrl, "?") === false) {
            $baseLoginUrl .= "?action=";
        } else {
            $baseLoginUrl .= "&action=";
        }
        if (empty($IdPMultiSupportInfo)) {
            $ssoUrl = $baseLoginUrl.'samlsso';
        } else {
            $ssoUrl = $baseLoginUrl.'samldiscovery';
        }
        $samlText = $this->get('saml_login_text', null, null, 'SAML Login');
        $samlTextPosition = $this->get('saml_login_text_position', null, null, 'top');
        $container = $this->getEvent()->getContent($authtype_base);

        if ($samlTextPosition == 'top') {
            $container->addContent('<center><a class="btn btn-default" href="'.$ssoUrl.'" title="SAML Login">'.$samlText.'</a></center><hr><br>', 'prepend');
        } else {
            $container->addContent('<div style="position: absolute;left:4%;top:207px;z-index:1;"><a class="btn btn-default" href="'.$ssoUrl.'" title="SAML Login">'.$samlText.'</a></div>', 'append');
        }

        $alternativeForgotPwUrl = $this->get('alternative_forgot_pw_url', null, null, '');
        if (!empty($alternativeForgotPwUrl)) {
            $js = '$( document ).ready(function() {
                    $(\'div.login-submit\').find(\'a\').first().attr(\'href\', "'.$alternativeForgotPwUrl.'");
            });';

            $container->addContent(CHtml::script($js));
        }
    }

    public function discoveryPage()
    {
        $IdPMultiSupportInfo = $this->getIdPMultiSupportInfo();
        $extractedIdPData = null;

        $idpDiscoveryMethod = $this->get('idp_discovery_method', null, null, 'idp_name');
        if (!isset($idpDiscoveryMethod)) {
            $idpDiscoveryMethod = 'idp_name';
        }

        if (!empty($IdPMultiSupportInfo)) {
            $IdPsData = json_decode($IdPMultiSupportInfo, true);
            if (!empty($IdPsData) && is_array($IdPsData)) {
                $baseLoginUrl = $this->api->createUrl('admin/authentication/sa/login', []);
                if (strpos($baseLoginUrl, "?") === false) {
                    $baseLoginUrl .= "?action=samlsso";
                } else {
                    $baseLoginUrl .= "&action=samlsso";
                }

                if ($idpDiscoveryMethod == 'custom') {
                    if (Yii::app()->request->getIsPostRequest()) {
                        // Used if the custom page requires user input, so we can retrieve it
                        $request = Yii::app()->request;
                        auth_saml2_hook_custom_discovery_page($this, $IdPsData, $baseLoginUrl, $request);
                    } else {
                        auth_saml2_hook_custom_discovery_page($this, $IdPsData, $baseLoginUrl, null);
                    }
                } else if ($idpDiscoveryMethod == 'idp_name' || $idpDiscoveryMethod == 'idp_entityid') {
                    echo 'Select the IdP:<br>';
                    echo '<ul>';
                    $name = $this->get('idp_name', null, null, '');
                    $entityId = $this->get('idp_entityid', null, null, '');
                    $identifier = $entityId;
                    if ($idpDiscoveryMethod == 'idp_name' && !empty($name)) {
                        $identifier = $name;
                    }

                    echo '<li><a href="'.$baseLoginUrl.'">'.$identifier.'</a></li>';
                    foreach ($IdPsData as $id => $IdPData) {
                        $identifier = $IdPData['entityid'];
                        if ($idpDiscoveryMethod == 'idp_name' && isset($IdPData['name']) && !empty($IdPData['name'])) {
                            $identifier = $IdPData['name'];
                        }
                        echo '<li><a href="'.$baseLoginUrl.'&idp='.$id.'">'.$identifier.'</a></li>';
                    }
                    echo '</ul>';
                }
                exit();
            } else {
                $this->log("SAML Login Error: Data of IdPs not found", \CLogger::LEVEL_ERROR);
                $this->showError(self::ERROR_NO_IDP, gT("Data of IdPs not found"));
            }
        } else {
            $this->log("SAML Login Error: Data of IdPs not found", \CLogger::LEVEL_ERROR);
            $this->showError(self::ERROR_NO_IDP, gT("Data of IdPs not found"));
        }
    }

    public function getUserName()
    {
        if ($this->_username == null) {
            $attributes = [];
            if (isset($_SESSION['samluser'])) {
                $attributes = $_SESSION['samluser'];
            }

            if (!empty($attributes)) {
                $saml_uid_mapping = $this->get('saml_uid_mapping', null, null, 'uid');
                $saml_uid_mapping_values = explode(',', $saml_uid_mapping);
                foreach($saml_uid_mapping_values as $saml_uid_mapping_value) {
                    if (isset($saml_uid_mapping_value) && array_key_exists($saml_uid_mapping_value, $attributes) && !empty($attributes[$saml_uid_mapping_value])) {
                        $username = $attributes[$saml_uid_mapping_value][0];
                        $this->setUsername($username);
                        break;
                    }
                }
            }
        }
        return $this->_username;
    }

    public function getUserCommonName()
    {
        $name = '';

        $attributes = [];
        if (isset($_SESSION['samluser'])) {
            $attributes = $_SESSION['samluser'];
        }

        if (!empty($attributes)) {
            $saml_name_mapping = $this->get('saml_name_mapping', null, null, 'cn');
            $saml_name_mapping_values = explode(',', $saml_name_mapping);
            foreach($saml_name_mapping_values as $saml_name_mapping_value) {
                if (isset($saml_name_mapping_value) && array_key_exists($saml_name_mapping_value, $attributes) && !empty($attributes[$saml_name_mapping_value])) {
                    $name = $attributes[$saml_name_mapping_value][0];
                    break;
                }
            }
        }
        return $name;
    }

    public function getUserMail()
    {
        $mail = '';

        $attributes = [];
        if (isset($_SESSION['samluser'])) {
            $attributes = $_SESSION['samluser'];
        }

        if (!empty($attributes)) {
            $saml_mail_mapping = $this->get('saml_mail_mapping', null, null, 'mail');
            $saml_mail_mapping_values = explode(',', $saml_mail_mapping);
            foreach($saml_mail_mapping_values as $saml_mail_mapping_value) {
                if (isset($saml_mail_mapping_value) && array_key_exists($saml_mail_mapping_value, $attributes) && !empty($attributes[$saml_mail_mapping_value])) {
                    $mail = $attributes[$saml_mail_mapping_value][0];
                    break;
                }
            }
        }
        return $mail;
    }

    public function getUserLang()
    {
        $lang = null;

        $attributes = [];
        if (isset($_SESSION['samluser'])) {
            $attributes = $_SESSION['samluser'];
        }

        if (!empty($attributes)) {
            $saml_lang_mapping = $this->get('saml_lang_mapping', null, null, null);
            if (isset($saml_lang_mapping)) {
                $saml_lang_mapping_values = explode(',', $saml_lang_mapping);
                foreach($saml_lang_mapping_values as $saml_lang_mapping_value) {
                    if ($saml_lang_mapping_value && array_key_exists($saml_lang_mapping_value, $attributes) && !empty($attributes[$saml_lang_mapping_value])) {
                        $lang = $attributes[$saml_lang_mapping_value][0];
                        break;
                    }
                }
            }
        }

        if (!empty($lang)) {
            $supportedLanguages = getLanguageData();
            if (!array_key_exists($lang, $supportedLanguages)) {
                $lang = null;
            }
        }

        return $lang;
    }

    public function getUserGroups($oUser)
    {
        $groups = null;
        $attributes = [];
        if (isset($_SESSION['samluser'])) {
            $attributes = $_SESSION['samluser'];
        }
        if (!empty($attributes)) {
            $saml_group_mapping = $this->get('saml_group_mapping', null, null, null);
            if (isset($saml_group_mapping)) {
                $saml_group_mapping_values = explode(',', $saml_group_mapping);
                foreach($saml_group_mapping_values as $saml_group_mapping_value) {
                    if ($saml_group_mapping_value && array_key_exists($saml_group_mapping_value, $attributes) && !empty($attributes[$saml_group_mapping_value])) {
                        $groups = $attributes[$saml_group_mapping_value];
                        break;
                    }
                }
            }
        }

        if ($groups && is_array($groups) && count($groups) == 1) {
            $groups = explode(",", $groups[0]);
        }

        $groups = auth_saml2_hook_extend_groups($this, $attributes, $groups, $oUser);

        return $groups;
    }

    public function newUserSession()
    {
        // Do nothing if this user is not AuthSAML2 type
        $identity = $this->getEvent()->get('identity');
        if ($identity->plugin != 'AuthSAML2') {
            return;
        }

        if (isset($_SESSION['samluser'])) {
            $sUser = $this->getUserName();

            $password = createPassword();
            $this->setPassword($password);

            $attributes = $_SESSION['samluser'];

            $user_data = [
                'name' => $this->getUserCommonName(),
                'mail' => $this->getUserMail(),
                'lang' => $this->getUserLang()
            ];

            $user_data = auth_saml2_hook_modify_userdata($this, $attributes, $user_data);

            if (!$this->validateUserData($sUser, $user_data)) {
                unset($_SESSION['samluser']);
                $this->log("SAML ACS Error: Required data not provided by IdP", \CLogger::LEVEL_ERROR);
                $this->showError(self::ERROR_UNKNOWN_IDENTITY, gT("Required data not provided by IdP"));
                return;
            }

            $name = $user_data['name'];
            $mail = $user_data['mail'];
            $lang = $user_data['lang'];

            if (empty($mail)) {
                $this->log("SAML ACS Error: User can not be created, no mail provided", \CLogger::LEVEL_ERROR);
                $this->showError(self::ERROR_USERNAME_INVALID, gT("User can not be created, no mail provided"));
                return;
            }

            $oUser = $this->api->getUserByName($sUser);
            if (is_null($oUser)) {
                // Create user
                $auto_create_users = $this->get('auto_create_users', null, null, true);
                if ($auto_create_users) {
                    $authorized = auth_saml2_hook_authorize_user_creation($this, $attributes, $user_data);
                    if ($authorized) {
                        // Create new user
                        $uid = User::model()->insertUser($sUser, $password, $name, 1, $mail);

                        if ($uid) {
                            Yii::app()->db->createCommand()->insert("saml_users", ["userid" => $uid]);

                            $this->managePermission($uid, $attributes);

                            if (!empty($lang)) {
                                User::model()->updateByPk($uid, ['lang' => $lang]);
                            }
                            // read again user from newly created entry
                            $oUser = $this->api->getUserByName($sUser);
                            $this->manageGroupData($oUser);

                            $oUser = auth_saml2_hook_before_successfully_login($this, $attributes, $oUser, false);

                            $this->pluginManager->dispatchEvent(new PluginEvent('newUserLogin', $this));
                            $this->setAuthSuccess($oUser);
                        } else {
                            unset($_SESSION['samluser']);
                            $this->log("SAML ACS Error: User can't be created: ".$mail, \CLogger::LEVEL_ERROR);
                            $this->showError(self::ERROR_USERNAME_INVALID, gT("User can't be created: ".$mail));
                        }
                    } else {
                        unset($_SESSION['samluser']);
                        $this->log("SAML ACS Error: User provisioning not authorized: ".$mail, CLogger::LEVEL_ERROR);
                        $this->showError(self::ERROR_UNKNOWN_IDENTITY, gT("User provisioning not authorized: ".$mail));
                    }
                } else {
                    unset($_SESSION['samluser']);
                    $this->log("SAML ACS Error: User provisioning disabled: ".$mail, CLogger::LEVEL_ERROR);
                    $this->showError(self::ERROR_UNKNOWN_IDENTITY, gT("User provisioning disabled: ".$mail));
                }
            } else {
                $authorized = auth_saml2_hook_authorize_user($this, $attributes, $user_data, $oUser);
                if ($authorized) {
                    // Update user?
                    $auto_update_users = $this->get('auto_update_users', null, null, true);
                    if ($auto_update_users) {
                        $changes = array (
                            'full_name' => $name,
                            'email' => $mail,
                        );

                        if (!empty($lang)) {
                            $changes['lang'] = $lang;
                        }

                        User::model()->updateByPk($oUser->uid, $changes);
                        $oUser = $this->api->getUserByName($sUser);
                    }
                    $this->manageGroupData($oUser, true);

                    $oUser = auth_saml2_hook_before_successfully_login($this, $attributes, $oUser, true);
                    $this->setAuthSuccess($oUser);
                } else {
                    unset($_SESSION['samluser']);
                    $this->log("SAML ACS Error: User not authorized: ".$mail, \CLogger::LEVEL_ERROR);
                    $this->showError(self::ERROR_UNKNOWN_IDENTITY, gT("User not authorized: ".$mail));
                }
            }
        }
    }

    private function getIdPMultiSupportInfo()
    {
        $value = $this->get('idp_multi_support', null, null, '');
        if ($value == "{}" || $value == "\"\"" || strlen($value) < 10) {
            $value = null;
        }

        return $value;
    }

    private function cleanCert($value)
    {
        return str_replace(['<div>','</div>'], "", trim($value));
    }

    private function validateUserData($username, $user_data)
    {
        if (empty($username)) {
            return false;
        }

        if (!isset($user_data['mail']) || empty($user_data['mail'])) {
            return false;
        }

        return true;
    }

    private function manageGroupData($oUser, $updating = false)
    {
        $sync_group_info = $this->get('sync_group', null, null, false);
        $auto_create_group = $this->get('auto_create_group', null, null, false);
        $groups = $this->getUserGroups($oUser);
        $group_objs = [];
        if ($groups != null) {
            foreach ($groups as $groupName) {
                $group = UserGroup::model()->findByAttributes(["name" => $groupName]);
                if (!$group && $auto_create_group) {
                    $this->addGroup($groupName);
                    $group = UserGroup::model()->findByAttributes(["name" => $groupName]);
                }

                if ($group) {
                    $group_objs[$group->ugid] = $group;
                }
            }
        }

        if ($updating) {
            $user_groups = UserInGroup::model()->findAllByAttributes(["uid" => $oUser->uid]);
            if (!empty($user_groups)) {
                foreach ($user_groups as $user_group) {
                    if (!array_key_exists($user_group->ugid, $group_objs)) {
                        $group = UserGroup::model()->findByAttributes(["ugid" => $user_group->ugid]);
                        // Remove old groups if sync active and not the owner
                        if ($sync_group_info && $group->owner_id != $oUser->uid) {
                            UserInGroup::model()->deleteByPk(['ugid' => $user_group->ugid, 'uid' => $oUser->uid]);
                        } else {
                            unset($group_objs[$user_group->ugid]);
                        }
                    } else {
                        unset($group_objs[$user_group->ugid]);
                    }
                }
            }
        }

        // Now add new groups
        if (!empty($group_objs)) {
            foreach ($group_objs as $group_obj) {
                UserInGroup::model()->insertRecords(['ugid' => $group_obj->ugid, 'uid' => $oUser->uid]);
            }
        }
    }

    private function addGroup($group_name)
    {
        $group_description = "Created by SAML Plugin";
        $iLoginID = 1;

        $iquery = "INSERT INTO {{user_groups}} (name, description, owner_id) VALUES(:group_name, :group_desc, :loginID)";
        $command = Yii::app()->db->createCommand($iquery)
                        ->bindParam(":group_name", $group_name, PDO::PARAM_STR)
                        ->bindParam(":group_desc", $group_description, PDO::PARAM_STR)
                        ->bindParam(":loginID", $iLoginID, PDO::PARAM_INT);
        $result = $command->query();
        if ($result) {
            // Checked
            $id = getLastInsertID(UserGroup::model()->tableName());
            if ($id > 0) {
                $user_in_groups_query = 'INSERT INTO {{user_in_groups}} (ugid, uid) VALUES (:ugid, :uid)';
                Yii::app()->db->createCommand($user_in_groups_query)
                    ->bindParam(":ugid", $id, PDO::PARAM_INT)
                    ->bindParam(":uid", $iLoginID, PDO::PARAM_INT)
                    ->query();
            }
            return $id;
        } else {
            return -1;
        }
    }

    private function managePermission($iNewUID, $attributes)
    {
        $permision_matrix = [];

        $entityPermission = $this->get('entity_permission', null, null, 'global');
        $entityIdPermission = $this->get('entity_id_permission', null, null, 0);

        $base = [
            'uid' => $iNewUID,
            'entity'=> $entityPermission,
            'entity_id' => intval($entityIdPermission)
        ];

        // Default template
        $defaultTemplate = Yii::app()->getConfig("defaulttemplate");
        if (empty($defaultTemplate)) {
            $defaultTemplate = Yii::app()->getConfig("defaulttheme");
            if (empty($defaultTemplate)) {
                $defaultTemplate = 'default';
            }
        }
        $permision_matrix[$defaultTemplate] = ['read_p' => 1];

        // Set permissions: Participant Panel
        $auto_create_permission_participant_panel = $this->get('auto_create_permission_participant_panel', null, null, true);
        if ($auto_create_permission_participant_panel) {
            $permision_matrix['participantpanel'] = [
                'create_p' => 1,
                'read_p' => 1,
                'update_p' => 1,
                'delete_p' => 1,
                'import_p' => 1,
                'export_p' => 1
            ];
        }

        // Set permissions: Label Sets
        $auto_create_permission_labelsets = $this->get('auto_create_permission_labelsets', null, null, true);
        if ($auto_create_permission_labelsets) {
            $permision_matrix['labelsets'] = [
                'create_p' => 1,
                'read_p' => 0,
                'update_p' => 0,
                'delete_p' => 0,
                'import_p' => 1,
                'export_p' => 1
            ];
        }

        // Set permissions: Settings & Plugins
        $auto_create_permission_settings_plugins = $this->get('auto_create_permission_settings_plugins', null, null, true);
        if ($auto_create_permission_settings_plugins) {
            $permision_matrix['settings'] = [
                'read_p' => 1,
                'update_p' => 1,
                'import_p' => 1
            ];
        }

        // Set permissions: surveys
        $auto_create_permission_surveys = $this->get('auto_create_permission_surveys', null, null, true);
        if ($auto_create_permission_surveys) {
            $permision_matrix['surveys'] = [
                'create_p' => 1,
                'read_p' => 0,
                'update_p' => 0,
                'delete_p' => 0,
                'export_p' => 0
            ];
        }

        // Set permissions: Templates
        $auto_create_permission_templates = $this->get('auto_create_permission_templates', null, null, true);
        if ($auto_create_permission_templates) {
            $permision_matrix['templates'] = [
                'create_p' => 1,
                'read_p' => 1,
                'update_p' => 1,
                'delete_p' => 1,
                'import_p' => 1,
                'export_p' => 1
            ];
        }

        // Set permissions: User Groups
        $auto_create_permission_user_groups = $this->get('auto_create_permission_user_groups', null, null, false);
        if ($auto_create_permission_user_groups) {
            $permision_matrix['usergroups'] = [
                'create_p' => 1,
                'read_p' => 1,
                'update_p' => 1,
                'delete_p' => 1
            ];
        }

        // Set permissions: Users
        $auto_create_permission_users = $this->get('auto_create_permission_users', null, null, false);
        if ($auto_create_permission_users) {
            $permision_matrix['users'] = [
                'create_p' => 1,
                'read_p' => 1,
                'update_p' => 1,
                'delete_p' => 1
            ];
        }

        // Set permissions: Superadministrator
        $auto_create_permission_superadministrator = $this->get('auto_create_permission_superadministrator', null, null, false);
        if ($auto_create_permission_superadministrator) {
            $permision_matrix['superadmin'] = [
                'create_p' => 1,
                'read_p' => 1
            ];
        }

        // Set permissions: Use internal database authentication
        $auto_create_permission_auth_db = $this->get('auto_create_permission_auth_db', null, null, true);
        if ($auto_create_permission_auth_db) {
            $permision_matrix['auth_db'] = [];
        }

        // Set permissions: auth_saml2
        $permision_matrix['auth_saml2'] = [];

        $permision_matrix = auth_saml2_hook_extend_permissions($this, $attributes, $permision_matrix);


        if (isset($permision_matrix['auth_db'])) {
            Permission::model()->setGlobalPermission($iNewUID, 'auth_db');
            unset($permision_matrix['auth_db']);
        }

        if (isset($permision_matrix['auth_saml2'])) {
            Permission::model()->setGlobalPermission($iNewUID, 'auth_saml2');
            unset($permision_matrix['auth_saml2']);
        }

        foreach ($permision_matrix as $permission => $info) {
            $data = array_merge($base, $info);
            $data['permission'] = $permission;
            Permission::model()->insertSomeRecords($data);
        }
    }
}
