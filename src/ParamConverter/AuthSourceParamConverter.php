<?php

namespace Drupal\samlauth\AuthSourceParamConverter;

use Drupal\Core\ParamConverter\ParamConverterInterface;
use Drupal\samlauth\Entity\AuthSource;
use Symfony\Component\Routing\Route;

class AuthSourceParamConverter implements ParamConverterInterface {
  public function convert($value, $definition, $name, array $defaults) {
      $query = \Drupal::entityQuery('authsource')
        ->condition('sp_entity_id', $value);
      $ids   = $query->execute();
      if ($auth_sources = AuthSource::loadMultiple($ids)) {
        return reset($auth_sources);
      }
      return NULL;
  }

  public function applies($definition, $name, Route $route) {
    return (!empty($definition['type']) && $definition['type'] == 'auth_source');
  }
}