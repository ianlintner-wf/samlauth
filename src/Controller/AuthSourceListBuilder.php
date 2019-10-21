<?php
namespace Drupal\samlauth\Controller;

use Drupal\Core\Config\Entity\ConfigEntityListBuilder;
use Drupal\Core\Entity\EntityInterface;

/**
 * Provides a listing of lotus.
 */
class AuthSourceListBuilder extends ConfigEntityListBuilder {
  /**
   * {@inheritdoc}
   */
  final public function buildHeader(): array {
    $header['label'] = $this->t('Example');
    $header['id'] = $this->t('Machine name');
    return $header + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  final public function buildRow(EntityInterface $entity): array {
    $row['label'] = $entity->label();
    $row['id'] = $entity->id();

    // You probably want a few more properties here...

    return $row + parent::buildRow($entity);
  }

  /**
   * Adds some descriptive text to our entity list.
   *
   * Typically, there's no need to override render(). You may wish to do so,
   * however, if you want to add markup before or after the table.
   *
   * @return array|mixed
   *   Renderable array.
   */
  final public function render() {
    $build[] = parent::render();
    return $build;
  }

}