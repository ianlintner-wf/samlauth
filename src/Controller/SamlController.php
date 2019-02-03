<?php

namespace Drupal\samlauth\Controller;

use Exception;
use Drupal\samlauth\SamlService;
use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Path\PathValidatorInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Url;
use Drupal\Core\Utility\Error;
use Drupal\Core\Utility\Token;
use OneLogin\Saml2\Utils;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;

/**
 * Returns responses for samlauth module routes.
 */
class SamlController extends ControllerBase {

  /**
   * The samlauth SAML service.
   *
   * @var \Drupal\samlauth\SamlService
   */
  protected $saml;

  /**
   * The request stack.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  protected $requestStack;

  /**
   * A configuration object containing samlauth settings.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

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
   * Constructor for Drupal\samlauth\Controller\SamlController.
   *
   * @param \Drupal\samlauth\SamlService $saml
   *   The samlauth SAML service.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request_stack
   *   The request stack.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Path\PathValidatorInterface $path_validator
   *   The PathValidator service.
   * @param \Drupal\Core\Utility\Token $token
   *   The token service.
   */
  public function __construct(SamlService $saml, RequestStack $request_stack, ConfigFactoryInterface $config_factory, PathValidatorInterface $path_validator, Token $token) {
    $this->saml = $saml;
    $this->requestStack = $request_stack;
    $this->config = $config_factory->get('samlauth.authentication');
    $this->pathValidator = $path_validator;
    $this->token = $token;
  }

  /**
   * Factory method for dependency injection container.
   *
   * @param \Symfony\Component\DependencyInjection\ContainerInterface $container
   *
   * @return static
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('samlauth.saml'),
      $container->get('request_stack'),
      $container->get('config.factory'),
      $container->get('path.validator'),
      $container->get('token')
    );
  }

  /**
   * Initiates a SAML2 authentication flow.
   *
   * This should redirect to the Login service on the IDP and then to our ACS.
   * It does not actually log us in (yet).
   */
  public function login() {
    try {
      $url = $this->saml->login($this->getUrlFromDestination());
    }
    catch (Exception $e) {
      $this->handleException($e, 'initiating SAML login');
      $url = Url::fromRoute('<front>');
    }

    return $this->createRedirectResponse($url);
  }

  /**
   * Initiate a SAML2 logout flow.
   *
   * This should redirect to the SLS service on the IDP and then to our SLS.
   * It does not actually log us out (yet).
   */
  public function logout() {
    try {
      $url = $this->saml->logout($this->getUrlFromDestination());
    }
    catch (Exception $e) {
      $this->handleException($e, 'initiating SAML logout');
      $url = Url::fromRoute('<front>');
    }

    return $this->createRedirectResponse($url);
  }

  /**
   * Displays service provider metadata XML for iDP autoconfiguration.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   */
  public function metadata() {
    try {
      $metadata = $this->saml->getMetadata();
    }
    catch (Exception $e) {
      $this->handleException($e, 'processing SAML SP metadata');
      return $this->createRedirectResponse(Url::fromRoute('<front>'));
    }

    return new Response($metadata, 200, ['Content-Type' => 'text/xml']);
  }

  /**
   * Attribute Consumer Service.
   *
   * This is usually the second step in the authentication flow; the Login
   * service on the IDP should redirect (or: execute a POST request to) here.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   */
  public function acs() {
    try {
      $this->saml->acs();
      $url = $this->getRedirectUrlAfterProcessing(TRUE);
    }
    catch (Exception $e) {
      $this->handleException($e, 'processing SAML authentication response');
      $url = Url::fromRoute('<front>');
    }

    return $this->createRedirectResponse($url);
  }

  /**
   * Single Logout Service.
   *
   * This is usually the second step in the logout flow; the SLS service on the
   * IDP should redirect here.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   */
  public function sls() {
    try {
      $url = $this->saml->sls();
      if (!$url) {
        $url = $this->getRedirectUrlAfterProcessing();
      }
    }
    catch (Exception $e) {
      $this->handleException($e, 'processing SAML single-logout response');
      $url = Url::fromRoute('<front>');
    }

    return $this->createRedirectResponse($url);
  }

  /**
   * Change password redirector.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   */
  public function changepw() {
    $url = $this->config->get('idp_change_password_service');
    return $this->createRedirectResponse($url);
  }

  /**
   * Constructs a full URL from the 'destination' parameter.
   *
   * @return string|null
   *   The full absolute URL (i.e. our hostname plus the path in the destination
   *   parameter), or NULL if no destination parameter was given. This value is
   *   tuned to what login() / logout() expect for an input argument.
   *
   * @throws \RuntimeException
   *   If the destination is disallowed.
   */
  protected function getUrlFromDestination() {
    $destination_url = NULL;
    $request_query_parameters = $this->requestStack->getCurrentRequest()->query;
    $destination = $request_query_parameters->get('destination');
    if ($destination) {
      if (UrlHelper::isExternal($destination)) {
        // Prevent authenticating and then redirecting somewhere else.
        throw new \RuntimeException("Destination URL query parameter must not be external: $destination");
      }
      // The destination parameter is relative by convention but fromUserInput()
      // requires it to start with '/'. (Note '#' and '?' don't make sense here
      // because that would be expanded to the current URL, which is saml/*.)
      if (strpos($destination, '/') !== 0) {
        $destination = "/$destination";
      }
      // toString(TRUE) will somehow tell Drupal we're taking care of
      // 'cacheability metadata' ourselves, which is in the GeneratedUrl object
      // that gets returned... and which we throw away because noone cares.
      // Still, we have to do this because a LogicException would get thrown
      // otherwise; see comments at createRedirectResponse().
      $destination_url = Url::fromUserInput($destination)->setAbsolute()->toString(TRUE)->getGeneratedUrl();
      // After we return from this controller, Drupal immediately redirects to
      // the path set in the 'destination' parameter - but we don't want that
      // to happen until after login, so remove parameter,
      $request_query_parameters->remove('destination');
    }

    return $destination_url;
  }

  /**
   * Returns a URL to redirect to.
   *
   * This should be called only after successfully processing an ACS/logout
   * response.
   *
   * @param bool $logged_in
   *   (optional) TRUE if an ACS request was just processed.
   *
   * @return \Drupal\Core\Url
   *   The URL to redirect to.
   */
  protected function getRedirectUrlAfterProcessing($logged_in = FALSE) {
    if (isset($_REQUEST['RelayState'])) {
      // We should be able to trust the RelayState parameter at this point
      // because the response from the IDP was verified. Only validate general
      // syntax.
      if (!UrlHelper::isValid($_REQUEST['RelayState'], TRUE)) {
        $this->getLogger('samlauth')->error('Invalid RelayState parameter found in request: @relaystate', ['@relaystate' => $_REQUEST['RelayState']]);
      }
      // The SAML toolkit set a default RelayState to itself (saml/log(in|out))
      // when starting the process; ignore this value.
      elseif (strpos($_REQUEST['RelayState'], Utils::getSelfURLhost() . '/saml/') !== 0) {
        $url = $_REQUEST['RelayState'];
      }
    }

    if (empty($url)) {
      // If no url was specified, we check if it was configured.
      $url = $this->config->get($logged_in ? 'login_redirect_url' : 'logout_redirect_url');
    }

    if ($url) {
      $url = $this->token->replace($url);
      // We don't check access here. If a URL was explicitly specified, we
      // prefer returning a 403 over silently redirecting somewhere else.
      $url_object = $this->pathValidator->getUrlIfValidWithoutAccessCheck($url);
      if (empty($url_object)) {
        $type = $logged_in ? 'Login' : 'Logout';
        $this->getLogger('samlauth')->warning("The $type Redirect URL is not a valid path; falling back to default.");
      }
    }

    if (empty($url_object)) {
      // If no url was configured, fall back to a hardcoded route.
      $url_object = Url::fromRoute($logged_in ? 'user.page' : '<front>');
    }

    return $url_object;
  }

  /**
   * Converts a URL to a response object that is suitable for this controller.
   *
   * @param string|\Drupal\Core\Url $url
   *   A URL to redirect to, either as a string or a Drupal URL object. Strings
   *   may only be used by callbacks that are configured in routing.yml as not
   *   being cacheable. (Which, in our case, is most callbacks.)
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   *   A response object representing a redirect.
   */
  protected function createRedirectResponse($url) {
    if (is_object($url)) {
      // Converting a URL object to a string representation is apparently
      // considered 'early rendering' by Drupal; we have to collect the
      // 'cacheability metadata' and add it to the request along with the URL
      // string. If we don't, a LogicException gets thrown later. (More info:
      // #2630808 / #2638686 / https://www.lullabot.com/articles/early-rendering-a-lesson-in-debugging-drupal-8)
      // toString(TRUE) will return a GeneratedUrl containing the metadata,
      // and tell Drupal that we're handling the metadata ourselves (which will
      // prevent the LogicException from being thrown, and also cancels the
      // need to add it to the response even though we do that anyway below).
      $generated_url = $url->toString(TRUE);
      $url = $generated_url->getGeneratedUrl();
    }
    // Also when having returned from the IDP, we might redirect to an external
    // url (at least in theory), so we always return a TrustedRedirectResponse.
    $response = new TrustedRedirectResponse($url);
    if (isset($generated_url)) {
      // We shouldn't have to add cacheability metadata to our response object
      // when the route is configured to not cache responses in our routing.yml.
      // Do it anyway to prevent future obscure bugs with new routes.
      $response->addCacheableDependency($generated_url);
    }

    return $response;
  }

  /**
   * Displays error message and logs full exception.
   *
   * @param $exception
   *   The exception thrown.
   * @param string $while
   *   A description of when the error was encountered.
   */
  protected function handleException($exception, $while = '') {
    if ($while) {
      $while = " $while";
    }
    // We use the same format for logging as Drupal's ExceptionLoggingSubscriber
    // except we also specify where the error was encountered. (The options are
    // limited, so we make this part of the message, not a context parameter.)
    $error = Error::decodeException($exception);
    unset($error['severity_level']);
    $this->getLogger('samlauth')->critical("%type encountered while $while: @message in %function (line %line of %file).", $error);
    // Don't expose the error to prevent information leakage; the user probably
    // can't do much with it anyway. But hint that more details are available.
    drupal_set_message("Error $while; details have been logged.", 'error');
  }

}
