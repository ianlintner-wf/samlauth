<?php

namespace Drupal\samlauth;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Url;
use Drupal\externalauth\ExternalAuth;
use Drupal\samlauth\Entity\AuthSource;
use Drupal\samlauth\Event\SamlauthEvents;
use Drupal\samlauth\Event\SamlauthUserLinkEvent;
use Drupal\samlauth\Event\SamlauthUserSyncEvent;
use  \Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\user\UserInterface;
use Exception;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Error;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * Governs communication between the SAML toolkit and the IDP / login behavior.
 */
class SamlService {

  /**
   * An Auth object representing the current request state.
   *
   * @var \OneLogin\Saml2\Auth
   */
  protected $samlAuth;

  /**
   * The ExternalAuth service.
   *
   * @var \Drupal\externalauth\ExternalAuth
   */
  protected $externalAuth;

  /**
   * A configuration object containing samlauth settings.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * The EntityTypeManager service.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * A logger instance.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * The event dispatcher.
   *
   * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
   */
  protected $eventDispatcher;

  /**
   * Private account session store.
   *
   * @var \Drupal\user\PrivateTempStore.
   */
  protected $privateTempStore;

  /***
   * @var \Drupal\Core\Entity\EntityStorageInterface
   */
  protected $authSourcesStorage;

  protected $authSources;

  /**
   * Constructor for Drupal\samlauth\SamlService.
   *
   * @param \Drupal\externalauth\ExternalAuth                           $external_auth
   *   The ExternalAuth service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface                  $config_factory
   *   The config factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface              $entity_type_manager
   *   The EntityTypeManager service.
   * @param \Psr\Log\LoggerInterface                                    $logger
   *   A logger instance.
   * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $event_dispatcher
   *   The event dispatcher.
   * @param \Drupal\Core\TempStore\PrivateTempStoreFactory              $temp_store_factory
   *   A temp data store factory object.
   *
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   * @throws \Drupal\Component\Plugin\Exception\PluginNotFoundException
   */
  public function __construct(ExternalAuth $external_auth, ConfigFactoryInterface $config_factory, EntityTypeManagerInterface $entity_type_manager, LoggerInterface $logger, EventDispatcherInterface $event_dispatcher, PrivateTempStoreFactory $temp_store_factory) {
    $this->externalAuth       = $external_auth;
    $this->config             = $config_factory->get('samlauth.authentication');
    $this->entityTypeManager  = $entity_type_manager;
    $this->logger             = $logger;
    $this->eventDispatcher    = $event_dispatcher;
    $this->privateTempStore   = $temp_store_factory->get('samlauth');
    $this->authSourcesStorage = $this->entityTypeManager->getStorage(
      'authsource');
    $this->authSources        = [];
  }

  /***
   * Get Auth Source
   *
   * @param $id
   *
   * @return bool|mixed
   */
  public function getAuthSource($id) {
    if (empty($this->authSources[$id])) {
      $this->authSources[$id] = $this->authSourcesStorage->load($id);
    }
    return empty($this->authSources[$id]) ? FALSE : $this->authSources[$id];
  }

  /**
   * Show metadata about the local sp. Use this to configure your saml2 IDP
   *
   * @return mixed xml string representing metadata
   * @throws \OneLogin\Saml2\Error
   */
  public function getMetadata(AuthSource $auth_source) {
    $settings = $this->getSamlAuth($auth_source)->getSettings();
    $metadata = $settings->getSPMetadata();
    $errors   = $settings->validateMetadata($metadata);

    if (empty($errors)) {
      return $metadata;
    }
    else {
      throw new RuntimeException(
        'Invalid SP metadata: ' . implode(', ', $errors),
        Error::METADATA_SP_INVALID);
    }
  }

  /**
   * Initiates a SAML2 authentication flow and redirects to the IDP.
   *
   * @param \Drupal\samlauth\Entity\AuthSource $auth_source
   * @param string                             $return_to
   *   (optional) The path to return the user to after successful processing by
   *   the IDP.
   *
   * @return string
   *   The URL of the single sign-on service to redirect to, including query
   *   parameters.
   */
  public function login(AuthSource $auth_source, $return_to = NULL) {
    return $this->getSamlAuth($auth_source)->login(
      $return_to,
      [],
      FALSE,
      FALSE,
      TRUE);
  }

  /**
   * Initiates a SAML2 logout flow and redirects to the IdP.
   *
   * @param \Drupal\samlauth\Entity\AuthSource $auth_source
   * @param null                               $return_to
   *   (optional) The path to return the user to after successful processing by
   *   the IDP.
   *
   * @return string
   *   The URL of the single logout service to redirect to, including query
   *   parameters.
   */
  public function logout(AuthSource $auth_source, $return_to = NULL) {

    return $this->getSamlAuth($auth_source)->logout(
      $return_to,
      [],
      $this->privateTempStore->get('name_id'),
      $this->privateTempStore->get('session_index'),
      TRUE,
      $this->privateTempStore->get('name_id_format')
    );
  }

  /**
   * Processes a SAML response (Assertion Consumer Service).
   * First checks whether the SAML request is OK, then takes action on the
   * Drupal user (logs in / maps existing / create new) depending on attributes
   * sent in the request and our module configuration.
   *
   * @param \Drupal\samlauth\Entity\AuthSource $auth_source
   *
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   * @throws \Drupal\Component\Plugin\Exception\PluginNotFoundException
   * @throws \Drupal\Core\Entity\EntityStorageException
   * @throws \Drupal\Core\TempStore\TempStoreException
   * @throws \Drupal\externalauth\Exception\ExternalAuthRegisterException
   */
  public function acs(AuthSource $auth_source) {
    if ($auth_source === NULL) {
      throw new RuntimeException('Auth Source Not Found');
    }
    // This call can either set an error condition or throw a
    // \OneLogin_Saml2_Error exception, depending on whether or not we are
    // processing a POST request. Don't catch the exception.
    $this->getSamlAuth($auth_source)->processResponse();
    // Now look if there were any errors and also throw.
    $errors = $this->getSamlAuth($auth_source)->getErrors();
    if (!empty($errors)) {
      // We have one or multiple error types / short descriptions, and one
      // 'reason' for the last error.
      throw new RuntimeException(
        'Error(s) encountered during processing of ACS response. Type(s): ' . implode(
          ', ',
          array_unique(
            $errors)) . '; reason given for last error: ' . $this->getSamlAuth(
          $auth_source)
          ->getLastErrorReason());
    }


    if (!$this->isAuthenticated($auth_source)) {
      throw new RuntimeException('Could not authenticate for ' . $auth_source->idp_entity_id);
    }

    $unique_id = $this->getAttributeByConfig('unique_id_attribute', $auth_source);
    if (!$unique_id) {
      throw new RuntimeException(
        'Configured unique ID is not present in SAML response.');
    }


    $account = $this->externalAuth->load($unique_id, 'samlauth');

    if (!$account) {
      $this->logger->debug(
        'No matching local users found for unique SAML ID @saml_id.',
        ['@saml_id' => $unique_id]);

      // Try to link an existing user: first through a custom event handler,
      // then by name, then by e-mail.
      if ($auth_source->get('map_users')) {
        $event = new SamlauthUserLinkEvent($this->getAttributes($auth_source));
        $this->eventDispatcher->dispatch(SamlauthEvents::USER_LINK, $event);
        $account = $event->getLinkedAccount();
        if (!$account) {
          // The linking by name / e-mail cannot be bypassed at this point
          // because it makes no sense to create a new account from the SAML
          // attributes if one of these two basic properties is already in use.
          // (In this case a newly created and logged-in account would get a
          // cryptic machine name because  synchronizeUserAttributes() cannot
          // assign the proper name while saving.)
          $name = $this->getAttributeByConfig('user_name_attribute', $auth_source);
          if ($name && $account_search = $this->entityTypeManager->getStorage(
              'user')->loadByProperties(['name' => $name])) {
            $account = reset($account_search);
            $this->logger->info(
              'Matching local user @uid found for name @name (as provided in a SAML attribute); associating user and logging in.',
              ['@name' => $name, '@uid' => $account->id()]);
          }
          else {
            $mail = $this->getAttributeByConfig('user_mail_attribute', $auth_source);
            if ($mail && $account_search = $this->entityTypeManager->getStorage(
                'user')->loadByProperties(['mail' => $mail])) {
              $account = reset($account_search);
              $this->logger->info(
                'Matching local user @uid found for e-mail @mail (as provided in a SAML attribute); associating user and logging in.',
                ['@mail' => $mail, '@uid' => $account->id()]);
            }
          }
        }
      }

      if ($account) {
        // There is a chance that the following call will not actually link the
        // account (if a mapping to this account already exists from another
        // unique ID). If that happens, it does not matter much to us; we will
        // just log the account in anyway. Next time the same not-yet-linked
        // user logs in, we will again try to link the account in the same way
        // and (falsely) log that we are associating the user.
        $this->externalAuth->linkExistingAccount(
          $unique_id,
          'samlauth',
          $account);
      }
    }

    // If we haven't found an account to link, create one from the SAML
    // attributes.
    if (!$account) {
      if ($auth_source->get('create_users')) {
        // The register() call will save the account. We want to:
        // - add values from the SAML response into the user account;
        // - not save the account twice (because if the second save fails we do
        //   not want to end up with a user account in an undetermined state);
        // - reuse code (i.e. call synchronizeUserAttributes() with its current
        //   signature, which is also done when an existing user logs in).
        // Because of the third point, we are not passing the necessary SAML
        // attributes into register()'s $account_data parameter, but we want to
        // hook into the save operation of the user account object that is
        // created by register(). It seems we can only do this by implementing
        // hook_user_presave() - which calls our synchronizeUserAttributes().
        $account = $this->externalAuth->register($unique_id, 'samlauth');

        $this->externalAuth->userLoginFinalize(
          $account,
          $unique_id,
          'samlauth');
      }
      else {
        throw new RuntimeException(
          'No existing user account matches the SAML ID provided. This authentication service is not configured to create new accounts.');
      }
    }
    elseif ($account->isBlocked()) {
      throw new RuntimeException('Requested account is blocked.');
    }
    else {
      // Synchronize the user account with SAML attributes if needed.
      $this->synchronizeUserAttributes($account, $auth_source);

      $this->externalAuth->userLoginFinalize(
        $account,
        $unique_id,
        'samlauth');
    }

    // Set some request properties in local private storage. We can use these on
    // logout.
    foreach ([
               'session_index'      => $this->samlAuth->getSessionIndex(),
               'session_expiration' => $this->samlAuth->getSessionExpiration(),
               'name_id'            => $this->samlAuth->getNameId(),
               'name_id_format'     => $this->samlAuth->getNameIdFormat(),
             ] as $key => $value
    ) {
      if (isset($value)) {
        $this->privateTempStore->set($key, $value);
      }
      else {
        $this->privateTempStore->delete($key);
      }
    }
}


/**
 * Does processing for the Single Logout Service.
 *   Usually returns nothing. May return a URL to redirect to.
 *
 * @param \Drupal\samlauth\Entity\AuthSource $auth_source
 *
 * @return mixed
 */
  public function sls(AuthSource $auth_source) {
    // This call can either set an error condition or throw a
    // \OneLogin_Saml2_Error exception, depending on whether or not we are
    // processing a POST request. Don't catch the exception.
    $url = $this->getSamlAuth($auth_source)->processSLO(
      FALSE,
      NULL,
      FALSE,
      NULL,
      TRUE);
    // Now look if there were any errors and also throw.
    $errors = $this->getSamlAuth($auth_source)->getErrors();
    if (!empty($errors)) {
      // We have one or multiple error types / short descriptions, and one
      // 'reason' for the last error.
      throw new RuntimeException(
        'Error(s) encountered during processing of SLS response. Type(s): ' . implode(
          ', ',
          array_unique(
            $errors)) . '; reason given for last error: ' . $this->getSamlAuth(
          $auth_source)
          ->getLastErrorReason());
    }

    // Usually we don't get any URL returned. The case in which we do, seems to
    // be something like IDP-initiated logout. Therefore we won't do further
    // processing.
    if (!$url) {
      // Delete private stored session information.
      foreach (['session_index', 'session_expiration'] as $key) {
        $this->privateTempStore->delete($key);
      }
      user_logout();
    }


    return $url;
  }

  /**
   * Synchronizes user data with attributes in the SAML request.
   *
   * @param \Drupal\user\UserInterface         $account
   *   The Drupal user to synchronize attributes into.
   * @param \Drupal\samlauth\Entity\AuthSource $auth_source
   * @param bool                               $skip_save
   *   (optional) If TRUE, skip saving the user account.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   */
  public function synchronizeUserAttributes(UserInterface $account, AuthSource $auth_source,bool $skip_save = FALSE) {
    // Dispatch a user_sync event.
    $event = new SamlauthUserSyncEvent($account, $this->getAttributes($auth_source), $auth_source);
    $this->eventDispatcher->dispatch(SamlauthEvents::USER_SYNC, $event);

    if (!$skip_save && $event->isAccountChanged()) {
      $account->save();
    }
  }

  /**
   * Returns all attributes in a SAML response.
   *
   * This method will return valid data after a response is processed (i.e.
   * after samlAuth->processResponse() is called).
   *
   * @return array
   *   An array with all returned SAML attributes..
   */
  public function getAttributes(AuthSource $auth_source) {
    return $this->getSamlAuth($auth_source)->getAttributes();
  }

  /**
   * Returns value from a SAML attribute whose name is configured in our module.
   * This method will return valid data after a response is processed (i.e.
   * after samlAuth->processResponse() is called).
   *
   * @param string                                  $config_key
   *   A key in the module's configuration, containing the name of a SAML
   *   attribute.
   * @param \Drupal\samlauth\Entity\AuthSource|null $auth_source
   *
   * @return mixed|null
   *   The SAML attribute value; NULL if the attribute value, or configuration
   *   key, was not found.
   */
  public function getAttributeByConfig($config_key, AuthSource $auth_source) {
    if ($auth_source !== NULL) {
      $attribute_name = $auth_source->get($config_key);

      if ($attribute_name) {
        $attribute = $this->getSamlAuth($auth_source)->getAttribute(
          $attribute_name);
        if (!empty($attribute[0])) {
          return $attribute[0];
        }
      }
    }
    return FALSE;
  }

  /**
   * @param \Drupal\samlauth\Entity\AuthSource $auth_source
   *
   * @return bool if a valid user was fetched from the saml assertion this request.
   */
  protected function isAuthenticated(AuthSource $auth_source) {
    return $this->getSamlAuth($auth_source)->isAuthenticated();
  }

  /**
   * Returns an initialized Auth class from the SAML Toolkit.
   *
   * @param \Drupal\samlauth\Entity\AuthSource $auth_source
   *
   * @return \OneLogin\Saml2\Auth
   */
  protected function getSamlAuth(AuthSource $auth_source) {
    if (!isset($this->samlAuth)) {

      $this->samlAuth = new Auth(static::reformatConfig($this->config, $auth_source));
    }

    return $this->samlAuth;
  }

  /**
   * Returns a configuration array as used by the external library.
   *
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The module configuration.
   * @param \Drupal\samlauth\Entity\AuthSource  $authSource
   *
   * @return array
   *   The library configuration array.
   */
  protected static function reformatConfig(ImmutableConfig $config, AuthSource $authSource)
  : array {
    // Check if we want to load the certificates from a folder. Either folder or
    // cert+key settings should be defined. If both are defined, "folder" is the
    // preferred method and we ignore cert/path values; we don't do more
    // complicated validation like checking whether the cert/key files exist.
    $sp_cert = '';
    $sp_key = '';
    $cert_folder = $authSource->get('sp_cert_folder');
    if ($cert_folder) {
      // Set the folder so the Simple SAML toolkit knows where to look.
      define('ONELOGIN_CUSTOMPATH', "$cert_folder/");
    }
    else {
      $sp_cert = $authSource->get('sp_x509_certificate');
      $sp_key = $authSource->get('sp_private_key');
    }

    $library_config = [
      'sp' => [
        'entityId' => $authSource->get('sp_entity_id'),
        'assertionConsumerService' => [
          // See SamlController::redirectResponseFromUrl() for details.
          'url' => Url::fromRoute('samlauth.saml_controller_acs', ['auth_source' => $authSource->sp_entity_id], ['absolute' => TRUE])->toString(TRUE)->getGeneratedUrl(),
        ],
        'singleLogoutService' => [
          'url' => Url::fromRoute('samlauth.saml_controller_sls', ['auth_source' => $authSource->sp_entity_id], ['absolute' => TRUE])->toString(TRUE)->getGeneratedUrl(),
        ],
        'NameIDFormat' => $authSource->get('sp_name_id_format'),
        'x509cert' => $sp_cert,
        'privateKey' => $sp_key,
      ],
      'idp' => [
        'entityId' => $authSource->get('idp_entity_id'),
        'singleSignOnService' => [
          'url' => $authSource->get('idp_single_sign_on_service'),
        ],
        'singleLogoutService' => [
          'url' => $authSource->get('idp_single_log_out_service'),
        ],
        'x509cert' => $authSource->get('idp_x509_certificate'),
      ],
      'security' => [
        'authnRequestsSigned' => (bool) $authSource->get('security_authn_requests_sign'),
        'logoutRequestSigned' => (bool) $authSource->get('security_logout_requests_sign'),
        'wantMessagesSigned' => (bool) $authSource->get('security_messages_sign'),
        'requestedAuthnContext' => (bool) $authSource->get('security_request_authn_context'),
        'lowercaseUrlencoding' => (bool) $authSource->get('security_lowercase_url_encoding'),
        'signatureAlgorithm' => $authSource->get('security_signature_algorithm'),
      ],
      'strict' => (bool) $authSource->get('strict'),
    ];

    /***
     * Protocol Binding Force
     */
    if (!empty($authSource->get('sp_acs_protocol_binding'))) {
      $library_config['sp']['assertionConsumerService']['binding'] = $authSource->get('sp_acs_protocol_binding');
    }
    if (!empty($authSource->get('sp_slo_protocol_binding'))) {
      $library_config['sp']['singleLogoutService']['binding'] = $authSource->get('sp_slo_protocol_binding');
    }
    // Check for the presence of a multi cert situation.
    $multi = $authSource->get('idp_cert_type');
    switch ($multi) {
      case "signing":
        $library_config['idp']['x509certMulti'] = array (
          'signing' => array (
            $authSource->get('idp_x509_certificate'),
            $authSource->get('idp_x509_certificate_multi'),
          )
        );
        break;
      case "encryption":
        $library_config['idp']['x509certMulti'] = array (
          'signing' => array (
            $authSource->get('idp_x509_certificate'),
          ),
          'encryption' => array (
            $authSource->get('idp_x509_certificate_multi'),
          ),
        );
        break;
    }

    return $library_config;
  }

}
