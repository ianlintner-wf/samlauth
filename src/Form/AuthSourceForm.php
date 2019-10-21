<?php
namespace Drupal\samlauth\Form;

use Drupal\Core\Entity\EntityForm;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Form handler for the lotus add and edit forms.
 */
class AuthSourceForm extends EntityForm {

  /**
   * Constructs an ExampleForm object.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entityTypeManager.
   */
  public function __construct(EntityTypeManagerInterface $entityTypeManager) {
    $this->entityTypeManager = $entityTypeManager;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('entity_type.manager')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function form(array $form, FormStateInterface $form_state) {
    $form = parent::form($form, $form_state);
    /***
     * @var \Drupal\samlauth\Entity\AuthSource $my_entity
     */
    $my_entity = $this->entity;

    $form['label'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Label'),
      '#maxlength' => 255,
      '#default_value' => $my_entity->label(),
      '#description' => $this->t("Label for the Example."),
      '#required' => TRUE,
    ];
    $form['id'] = [
      '#type' => 'machine_name',
      '#default_value' => $my_entity->id(),
      '#machine_name' => [
        'exists' => [$this, 'exist'],
      ],
      '#disabled' => !$my_entity->isNew(),
    ];

    $form['service_provider'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Service Provider Configuration'),
    ];

    $form['service_provider']['config_info'] = [
      '#theme' => 'item_list',
      '#items' => [
        $this->t('Metadata URL') . ': ' . \Drupal::urlGenerator()->generateFromRoute('samlauth.saml_controller_metadata', [], ['absolute' => TRUE]),
        $this->t('Assertion Consumer Service') . ': ' . Url::fromRoute('samlauth.saml_controller_acs', [], ['absolute' => TRUE])->toString(),
        $this->t('Single Logout Service') . ': ' . Url::fromRoute('samlauth.saml_controller_sls', [], ['absolute' => TRUE])->toString(),
      ],
      '#empty' => [],
      '#list_type' => 'ul',
    ];

    $form['service_provider']['sp_entity_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Entity ID'),
      '#description' => $this->t('Specifies the identifier to be used to represent the SP.'),
      '#default_value' => $my_entity->sp_entity_id,
    ];

    $form['service_provider']['sp_name_id_format'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Name ID Format'),
      '#description' => $this->t('Specify the NameIDFormat attribute to request from the identity provider'),
      '#default_value' => $my_entity->sp_name_id_format,
    ];

    $cert_folder = $my_entity->sp_cert_folder;
    $sp_x509_certificate = $my_entity->sp_x509_certificate;
    $sp_private_key = $my_entity->sp_private_key;

    $form['service_provider']['sp_cert_type'] = [
      '#type' => 'select',
      '#title' => $this->t('Type of configuration to save for the certificates'),
      '#required' => TRUE,
      '#options' => [
        'folder' => $this->t('Folder name'),
        'fields' => $this->t('Cert/key value'),
      ],
      // Prefer folder over certs, like SamlService::reformatConfig(), but if
      // both are empty then default to folder here.
      '#default_value' => $cert_folder || (!$sp_x509_certificate && !$sp_private_key) ? 'folder' : 'fields',
    ];

    $form['service_provider']['sp_x509_certificate'] = [
      '#type' => 'textarea',
      '#title' => $this->t('x509 Certificate'),
      '#description' => $this->t('Public x509 certificate of the SP. No line breaks or BEGIN CERTIFICATE or END CERTIFICATE lines.'),
      '#default_value' => $my_entity->sp_x509_certificate,
      '#states' => [
        'visible' => [
          [':input[name="sp_cert_type"]' => ['value' => 'fields']],
        ],
      ],
    ];

    $form['service_provider']['sp_private_key'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Private Key'),
      '#description' => $this->t('Private key for SP. No line breaks or BEGIN CERTIFICATE or END CERTIFICATE lines.'),
      '#default_value' => $my_entity->sp_private_key,
      '#states' => [
        'visible' => [
          [':input[name="sp_cert_type"]' => ['value' => 'fields']],
        ],
      ],
    ];

    $form['service_provider']['sp_cert_folder'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Certificate folder'),
      '#description' => $this->t('Set the path to the folder containing a /certs subfolder and the /certs/sp.key (private key) and /certs/sp.crt (public cert) files. The names of the subfolder and files are mandated by the external SAML Toolkit library.'),
      '#default_value' => $cert_folder,
      '#states' => [
        'visible' => [
          [':input[name="sp_cert_type"]' => ['value' => 'folder']],
        ],
      ],
    ];

    $form['identity_provider'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Identity Provider Configuration'),
    ];

    // @TODO: Allow a user to automagically populate this by providing a metadata URL for the iDP.
    //    $form['identity_provider']['idp_metadata_url'] = [
    //      '#type' => 'url',
    //      '#title' => $this->t('Metadata URL'),
    //      '#description' => $this->t('URL of the XML metadata for the identity provider'),
    //      '#default_value' => $my_entity->idp_metadata_url'),
    //    ];

    $form['identity_provider']['idp_entity_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Entity ID'),
      '#description' => $this->t('Specifies the identifier to be used to represent the IDP.'),
      '#default_value' => $my_entity->idp_entity_id,
    ];

    $form['identity_provider']['idp_single_sign_on_service'] = [
      '#type' => 'url',
      '#title' => $this->t('Single Sign On Service'),
      '#description' => $this->t('URL where the SP will send the authentication request message.'),
      '#default_value' => $my_entity->idp_single_sign_on_service,
    ];

    $form['identity_provider']['idp_single_log_out_service'] = [
      '#type' => 'url',
      '#title' => $this->t('Single Logout Service'),
      '#description' => $this->t('URL where the SP will send the logout request message.'),
      '#default_value' => $my_entity->idp_single_log_out_service,
    ];

    $form['identity_provider']['idp_change_password_service'] = [
      '#type' => 'url',
      '#title' => $this->t('Change Password Service'),
      '#description' => $this->t('URL where users will be redirected to change their password.'),
      '#default_value' => $my_entity->idp_change_password_service,
    ];

    $form['identity_provider']['idp_cert_type'] = [
      '#type' => 'select',
      '#title' => $this->t('Single/Multi Cert'),
      '#required' => TRUE,
      '#options' => [
        'single' => $this->t('Single Cert'),
        'signing' => $this->t('Key Rollover Phase'),
        'encryption' => $this->t('Unique Signing/Encryption'),
      ],
      '#default_value' => $my_entity->idp_cert_type ?  $my_entity->idp_cert_type : 'single',
    ];

    $form['identity_provider']['idp_x509_certificate'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Primary x509 Certificate'),
      '#description' => $this->t('Public x509 certificate of the IdP. The external SAML Toolkit library does not allow configuring this as a separate file.'),
      '#default_value' => $my_entity->idp_x509_certificate,
    ];

    $form['identity_provider']['idp_x509_certificate_multi'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Secondary x509 Certificate'),
      '#description' => $this->t('Secondary public x509 certificate of the IdP. This is a signing key if using "Key Rollover Phase" and an encryption key if using "Unique Signing/Encryption."'),
      '#default_value' => $my_entity->idp_x509_certificate_multi,
      '#states' => [
        'invisible' => [
          ':input[name="idp_cert_type"]' => ['value' => 'single'],
        ],
      ],
    ];

    $form['user_info'] = [
      '#title' => $this->t('User Info and Syncing'),
      '#type' => 'fieldset',
    ];

    $form['user_info']['unique_id_attribute'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Unique identifier attribute'),
      '#description' => $this->t("Specify a SAML attribute that is always going to be unique per user. This will be used to identify local users through an 'auth mapping' (which is stored separately from the user account info).<br>Example: <em>eduPersonPrincipalName</em> or <em>eduPersonTargetedID</em>"),
      '#default_value' => $my_entity->unique_id_attribute ?: 'eduPersonTargetedID',
    ];

    $form['user_info']['map_users'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Attempt to map SAML users to existing local users'),
      '#description' => $this->t('If this option is enabled and the SAML authentication response is not mapped to a user yet, but the name / e-mail attribute matches an existing non-mapped user, the SAML user will be mapped to the user.'),
      '#default_value' => $my_entity->map_users,
    ];

    $form['user_info']['create_users'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Create users specified by SAML server'),
      '#description' => $this->t('If this option is enabled and the SAML authentication response is not mapped to a user, a new user is created using the name / e-mail attributes from the response.'),
      '#default_value' => $my_entity->create_users,
    ];

    $form['user_info']['sync_name'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Synchronize user name on every login'),
      '#default_value' => $my_entity->sync_name,
      '#description' => $this->t('If this option is enabled, any changes to the name of SAML users will be propagated into Drupal user accounts.'),
    ];

    $form['user_info']['sync_mail'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Synchronize email address on every login'),
      '#default_value' => $my_entity->sync_mail,
      '#description' => $this->t('If this option is enabled, any changes to the email address of SAML users will be propagated into Drupal user accounts.'),
    ];

    $form['user_info']['user_name_attribute'] = [
      '#type' => 'textfield',
      '#title' => $this->t('User name attribute'),
      '#description' => $this->t('When SAML users are mapped / created, this field specifies which SAML attribute should be used for the Drupal user name.<br />Example: <em>cn</em> or <em>eduPersonPrincipalName</em>'),
      '#default_value' => $my_entity->user_name_attribute ?: 'cn',
      '#states' => [
        'invisible' => [
          ':input[name="map_users"]' => ['checked' => FALSE],
          ':input[name="create_users"]' => ['checked' => FALSE],
          ':input[name="sync_name"]' => ['checked' => FALSE],
        ],
      ],
    ];

    $form['user_info']['user_mail_attribute'] = [
      '#type' => 'textfield',
      '#title' => $this->t('User email attribute'),
      '#description' => $this->t('When SAML users are mapped / created, this field specifies which SAML attribute should be used for the Drupal email address.<br />Example: <em>mail</em>'),
      '#default_value' => $my_entity->user_mail_attribute ?: 'email',
      '#states' => [
        'invisible' => [
          ':input[name="map_users"]' => ['checked' => FALSE],
          ':input[name="create_users"]' => ['checked' => FALSE],
          ':input[name="sync_mail"]' => ['checked' => FALSE],
        ],
      ],
    ];

    $form['security'] = [
      '#title' => $this->t('Security Options'),
      '#type' => 'fieldset',
    ];

    $form['security']['strict'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Strict mode'),
      '#description' => $this->t('In strict mode, any validation failures or unsigned SAML messages which are requested to be signed (according to your settings) will cause the SAML conversation to be terminated. In production environments, this <em>must</em> be set.'),
      '#default_value' => $my_entity->strict,
    ];

    $form['security']['security_authn_requests_sign'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Sign authentication requests'),
      '#description' => $this->t('Requests sent to the Single Sign-On Service of the IDP will include a signature.'),
      '#default_value' => $my_entity->security_authn_requests_sign,
    ];

    $form['security']['security_logout_requests_sign'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Sign logout requests'),
      '#description' => $this->t('Requests sent to the Single Logout Service of the IDP will include a signature.'),
      '#default_value' => $my_entity->security_logout_requests_sign,
    ];

    $form['security']['security_signature_algorithm'] = [
      '#type' => 'select',
      '#title' => $this->t('Signature algorithm'),
      // The first option is the library default.
      '#options' => [
        'http://www.w3.org/2000/09/xmldsig#rsa-sha1' => 'RSA-sha1',
        'http://www.w3.org/2000/09/xmldsig#hmac-sha1' => 'HMAC-sha1',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => 'sha256',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => 'sha384',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => 'sha512'
      ],
      '#description' => $this->t('Algorithm used in the signing process.'),
      '#default_value' => $my_entity->security_signature_algorithm,
      '#states' => [
        'visible' => [
          [':input[name="security_authn_requests_sign"]' => ['checked' => TRUE]],
          'or',
          [':input[name="security_logout_requests_sign"]' => ['checked' => TRUE]],
        ],
      ],
    ];

    $form['security']['security_messages_sign'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Request messages to be signed'),
      '#description' => $this->t('Response messages from the IDP are expected to be signed.'),
      '#default_value' => $my_entity->security_messages_sign,
      '#states' => [
        'disabled' => [
          ':input[name="strict"]' => ['checked' => FALSE],
        ],
      ],
    ];

    $form['security']['security_request_authn_context'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Request authn context'),
      '#default_value' => $my_entity->security_request_authn_context,
    ];


    $form['security']['security_lowercase_url_encoding'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Encode urls in lowercase'),
      '#description' => $this->t('ADFS encodes urls as lowercase and the library does it so in uppercase. When using ADFS and signature verification, this setting must be enabled.'),
      '#default_value' => $my_entity->security_lowercase_url_encoding,
    ];


    // You will need additional form elements for your custom properties.
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function save(array $form, FormStateInterface $form_state) {
    $my_entity = $this->entity;
    $status = $my_entity->save();

    if ($status) {
      $this->messenger()->addMessage($this->t('Saved the %label Authsource.', [
        '%label' => $my_entity->label(),
      ]));
    }
    else {
      $this->messenger()->addMessage($this->t('The %label AuthSource was not saved.', [
        '%label' => $my_entity->label(),
      ]), MessengerInterface::TYPE_ERROR);
    }

    $form_state->setRedirect('entity.authsource.collection');
  }

  /**
   * Helper function to check whether an Authsource configuration entity exists.
   */
  public function exist($id) {
    $entity = $this->entityTypeManager->getStorage('authsource')->getQuery()
      ->condition('id', $id)
      ->execute();
    return (bool) $entity;
  }

}