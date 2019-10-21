<?php

namespace Drupal\samlauth\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Path\PathValidatorInterface;
use Drupal\Core\Url;
use Drupal\Core\Utility\Token;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Provides a configuration form for samlauth module settings and IDP/SP info.
 */
class SamlauthConfigureForm extends ConfigFormBase {

  /**
   * The PathValidator service.
   *
   * @var \Drupal\Core\Path\PathValidatorInterface
   */
  protected $pathValidator;

  /**
   * The token service.
   *
   * @var \Drupal\Core\Utility\Token
   */
  protected $token;

  /**
   * Constructs a \Drupal\samlauth\Form\SamlauthConfigureForm object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The factory for configuration objects.
   * @param \Drupal\Core\Path\PathValidatorInterface $path_validator
   *   The PathValidator service.
   * @param \Drupal\Core\Utility\Token $token
   *   The token service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, PathValidatorInterface $path_validator, Token $token) {
    parent::__construct($config_factory);
    $this->pathValidator = $path_validator;
    $this->token = $token;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory'),
      $container->get('path.validator'),
      $container->get('token')
    );
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'samlauth.authentication'
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'samlauth_configure_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('samlauth.authentication');

    $form['saml_login_logout'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Login / Logout'),
    ];

    // Show note for enabling "log in" or "log out" menu link item.
    if (Url::fromRoute('entity.menu.edit_form', ['menu' => 'account'])->access()) {
      $form['saml_login_logout']['menu_item'] = [
        '#type' => 'markup',
        '#markup' => '<em>' . $this->t('Note: You <a href="@url">may want to enable</a> the "log in" / "log out" menu item and disable the original one.', [
            '@url' => Url::fromRoute('entity.menu.edit_form', ['menu' => 'account'])
              ->toString()
          ]) . '</em>',
      ];
    }

    $form['saml_login_logout']['login_menu_item_title'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Login menu item title'),
      '#description' => $this->t('The title of the SAML login link. Defaults to "Log in".'),
      '#default_value' => $config->get('login_menu_item_title'),
    ];

    $form['saml_login_logout']['logout_menu_item_title'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Logout menu item title'),
      '#description' => $this->t('The title of the SAML logout link. Defaults to "Log out".'),
      '#default_value' => $config->get('logout_menu_item_title'),
    ];

    $form['saml_login_logout']['drupal_saml_login'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Allow SAML users to log in directly'),
      '#description' => $this->t('If this option is enabled, users that have a remote SAML ID will also be allowed to log in through the normal Drupal process (without the intervention of the configured identity provider). This option does not change anything to site layout (e.g. enabling menu links); you will need to do this yourself.'),
      '#default_value' => $config->get('drupal_saml_login'),
    ];

    $form['saml_login_logout']['login_redirect_url'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Login redirect URL'),
      '#description' => $this->t("Define the default URL to redirect the user after login. Enter a internal path starting with a slash, or a absolute URL. Defaults to the logged-in user's account page."),
      '#default_value' => $config->get('login_redirect_url'),
    ];

    $form['saml_login_logout']['logout_redirect_url'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Logout redirect URL'),
      '#description' => $this->t('Define the default URL to redirect the user after logout. Enter a internal path starting with a slash, or a absolute URL. Defaults to the front page.'),
      '#default_value' => $config->get('logout_redirect_url'),
    ];


    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    parent::validateForm($form, $form_state);
    // @TODO: Validate cert. Might be able to just openssl_x509_parse().

    // Validate login/logout redirect URLs.
    $login_url_path = $form_state->getValue('login_redirect_url');
    if ($login_url_path) {
      $login_url_path = $this->token->replace($login_url_path);
      $login_url = $this->pathValidator->getUrlIfValidWithoutAccessCheck($login_url_path);
      if (!$login_url) {
        $form_state->setErrorByName('login_redirect_url', $this->t('The Login Redirect URL is not a valid path.'));
      }
    }
    $logout_url_path = $form_state->getValue('logout_redirect_url');
    if ($logout_url_path) {
      $logout_url_path = $this->token->replace($logout_url_path);
      $logout_url = $this->pathValidator->getUrlIfValidWithoutAccessCheck($logout_url_path);
      if (!$logout_url) {
        $form_state->setErrorByName('logout_redirect_url', $this->t('The Logout Redirect URL is not a valid path.'));
      }
    }

    // Validate certs folder. Don't allow the user to save an empty folder; if
    // they want to save incomplete config data, they can switch to 'fields'.
    $sp_cert_type = $form_state->getValue('sp_cert_type');
    $sp_cert_folder = $this->fixFolderPath($form_state->getValue('sp_cert_folder'));
    if ($sp_cert_type == 'folder') {
      if (empty($sp_cert_folder)) {
        $form_state->setErrorByName('sp_cert_folder', $this->t('@name field is required.', ['@name' => $form['service_provider']['sp_cert_folder']['#title']]));
      }
      elseif (!file_exists($sp_cert_folder . '/certs/sp.key') || !file_exists($sp_cert_folder . '/certs/sp.crt')) {
        $form_state->setErrorByName('sp_cert_folder', $this->t('The Certificate folder does not contain the required certs/sp.key or certs/sp.crt files.'));
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    parent::submitForm($form, $form_state);

    // Only store variables related to the sp_cert_type value. (If the user
    // switched from fields to folder, the cert/key values always get cleared
    // so no unused security sensitive data gets saved in the database.)
    $sp_cert_type = $form_state->getValue('sp_cert_type');
    $sp_x509_certificate = '';
    $sp_private_key = '';
    $sp_cert_folder = '';
    if ($sp_cert_type == 'folder') {
      $sp_cert_folder = $this->fixFolderPath($form_state->getValue('sp_cert_folder'));
    }
    else {
      $sp_x509_certificate = $form_state->getValue('sp_x509_certificate');
      $sp_private_key = $form_state->getValue('sp_private_key');
    }

    $this->config('samlauth.authentication')
      ->set('login_menu_item_title', $form_state->getValue('login_menu_item_title'))
      ->set('logout_menu_item_title', $form_state->getValue('logout_menu_item_title'))
      ->set('drupal_saml_login', $form_state->getValue('drupal_saml_login'))
      ->set('login_redirect_url', $form_state->getValue('login_redirect_url'))
      ->set('logout_redirect_url', $form_state->getValue('logout_redirect_url'))
      ->set('authsource', $form_state->getValidateHandlers('authsource'))
      ->save();
  }

  /**
   * Remove trailing slash from a folder name, to unify config values.
   */
  private function fixFolderPath($path) {
    if ($path) {
      $path =  rtrim($path, '/');
    }
    return $path;
  }

}
