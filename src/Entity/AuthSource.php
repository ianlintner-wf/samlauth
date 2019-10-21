<?php
namespace Drupal\samlauth\Entity;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\samlauth\AuthSourceInterface;


/**
 * Defines the lotus entity.
 *
 * @ConfigEntityType(
 *   id = "authsource",
 *   label = @Translation("Auth Source"),
 *   handlers = {
 *     "list_builder" = "Drupal\samlauth\Controller\AuthSourceListBuilder",
 *     "form" = {
 *       "add" = "Drupal\samlauth\Form\AuthSourceForm",
 *       "edit" = "Drupal\samlauth\Form\AuthSourceForm",
 *       "delete" = "Drupal\samlauth\Form\AuthSourceDeleteForm",
 *     }
 *   },
 *   config_prefix = "authsource",
 *   admin_permission = "administer site configuration",
 *   entity_keys = {
 *     "id" = "sp_entity_id",
 *     "label" = "label",
 *     "login_menu_item_title" = "login_menu_item_title",
 *     "sp_entity_id" = "sp_entity_id",
 *     "sp_name_id_format" = "sp_name_id_format",
 *     "sp_cert_folder" = "sp_cert_folder",
 *     "sp_x509_certificate" = "sp_x509_certificate",
 *     "sp_private_key" = "sp_private_key",
 *     "idp_enity_id" = "idp_enity_id",
 *     "idp_single_sign_on_service" = "idp_single_sign_on_service",
 *     "idp_single_log_out_service" = "idp_single_log_out_service",
 *     "idp_change_password_service" = "idp_change_password_service",
 *     "idp_cert_type" = "idp_cert_type",
 *     "idp_x509_certificate" = "idp_x509_certificate",
 *     "idp_x509_certificate_multi" = "idp_x509_certificate_multi",
 *     "unique_id_attribute" = "unique_id_attribute",
 *     "map_users" = "map_users",
 *     "create_users" = "create_users",
 *     "sync_name" = "sync_name",
 *     "sync_mail" = "sync_mail",
 *     "user_name_attribute" = "user_name_attribute",
 *     "user_mail_attribute" = "user_mail_attribute",
 *     "strict" = "strict",
 *     "security_authn_requests_sign" = "security_authn_requests_sign",
 *     "security_logout_requests_sign" = "security_logout_requests_sign",
 *     "security_signature_algorithm" = "security_signature_algorithm",
 *     "security_messages_sign" = "security_messages_sign",
 *     "security_request_authn_context" = "security_request_authn_context",
 *     "security_lowercase_url_encoding" = "security_lowercase_url_encoding",
 *   },
 *   links = {
 *     "add-form"  = "/admin/config/people/saml/authsource/add",
 *     "edit-form" = "/admin/config/people/saml/authsource/{authsource}",
 *     "delete-form" = "/admin/config/people/saml/authsource/{authsource}/delete",
 *   }
 * )
 */
class AuthSource extends ConfigEntityBase implements AuthSourceInterface {

  /**
   * The IAuthSource ID.
   *
   * @var string
   */
  public $id;

  /**
   * The IAuthSource label.
   *
   * @var string
   */
  public $label;

  public $login_menu_item_title;
  public $sp_entity_id;
  public $sp_name_id_format;
  public $sp_cert_folder;
  public $sp_x509_certificate;
  public $sp_private_key;
  public $idp_enity_id;
  public $idp_single_sign_on_service;
  public $idp_single_log_out_service;
  public $idp_change_password_service;
  public $idp_cert_type;
  public $idp_x509_certificate;
  public $idp_x509_certificate_multi;
  public $unique_id_attribute;
  public $map_users;
  public $create_users;
  public $sync_name;
  public $sync_mail;
  public $user_name_attribute;
  public $user_mail_attribute;
  public $strict;
  public $security_authn_requests_sign;
  public $security_logout_requests_sign;
  public $security_signature_algorithm;
  public $security_messages_sign;
  public $security_request_authn_context;
  public $security_lowercase_url_encoding;

  // Your specific configuration property get/set methods go here,
  // implementing the interface.

}