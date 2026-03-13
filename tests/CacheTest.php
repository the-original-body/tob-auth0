<?php

declare(strict_types=1);

namespace Tests\TobAuth0;

use PHPUnit\Framework\TestCase;
use Tob\Auth0\Cache\WpObjectCacheItem;
use Tob\Auth0\Cache\WpObjectCachePool;

class CacheTest extends TestCase
{
    // -- WpObjectCacheItem -----------------------------------------------------

    public function testCacheItemMissIsNotHit(): void
    {
        $item = WpObjectCacheItem::miss('test_key');

        $this->assertSame('test_key', $item->getKey());
        $this->assertFalse($item->isHit());
        $this->assertNull($item->get());
    }

    public function testCacheItemSetMarksAsHit(): void
    {
        $item = WpObjectCacheItem::miss('key');
        $item->set('value');

        $this->assertTrue($item->isHit());
        $this->assertSame('value', $item->get());
    }

    public function testCacheItemExpiresAfterInt(): void
    {
        $item = new WpObjectCacheItem('key', 'val', true);
        $before = time();
        $item->expiresAfter(300);

        $this->assertGreaterThanOrEqual($before + 300, $item->expirationTimestamp());
        $this->assertLessThanOrEqual($before + 301, $item->expirationTimestamp());
    }

    public function testCacheItemExpiresAfterNull(): void
    {
        $item = new WpObjectCacheItem('key', 'val', true);
        $item->expiresAfter(300);
        $item->expiresAfter(null);

        $this->assertNull($item->expirationTimestamp());
    }

    public function testCacheItemExpiresAfterDateInterval(): void
    {
        $item = new WpObjectCacheItem('key', 'val', true);
        $item->expiresAfter(new \DateInterval('PT1H'));

        // Should be approximately now + 1 hour
        $this->assertNotNull($item->expirationTimestamp());
    }

    public function testCacheItemExpiresAt(): void
    {
        $item = new WpObjectCacheItem('key', 'val', true);
        $future = new \DateTimeImmutable('+1 hour');
        $item->expiresAt($future);

        $this->assertSame($future->getTimestamp(), $item->expirationTimestamp());
    }

    public function testCacheItemExpiresAtNull(): void
    {
        $item = new WpObjectCacheItem('key', 'val', true);
        $item->expiresAt(null);

        $this->assertNull($item->expirationTimestamp());
    }

    // -- WpObjectCachePool -----------------------------------------------------

    public function testPoolGetItemReturnsMissForUnknownKey(): void
    {
        $pool = new WpObjectCachePool();
        $item = $pool->getItem('nonexistent_pool_key');

        $this->assertFalse($item->isHit());
    }

    public function testPoolHasItemReturnsFalseForUnknownKey(): void
    {
        $pool = new WpObjectCachePool();
        $this->assertFalse($pool->hasItem('nonexistent_pool_key'));
    }

    public function testPoolDeleteItemDoesNotThrow(): void
    {
        $pool = new WpObjectCachePool();
        $result = $pool->deleteItem('nonexistent_delete_key');

        // wp_cache_delete returns false if key doesn't exist, that's ok
        $this->assertIsBool($result);
    }

    public function testPoolDeleteItemsReturnsBool(): void
    {
        $pool = new WpObjectCachePool();
        $result = $pool->deleteItems(['key1', 'key2']);

        $this->assertIsBool($result);
    }

    public function testPoolGetItemsReturnsEmptyForEmptyKeys(): void
    {
        $pool = new WpObjectCachePool();
        $items = $pool->getItems([]);

        $this->assertSame([], $items);
    }

    public function testPoolSaveDeferredAndCommit(): void
    {
        $pool = new WpObjectCachePool();
        $item = new WpObjectCacheItem('deferred_key', 'deferred_value', true);
        $item->expiresAfter(60);

        $this->assertTrue($pool->saveDeferred($item));
        $this->assertTrue($pool->commit());
    }

    public function testPoolSaveRejectsNonWpObjectCacheItem(): void
    {
        $pool = new WpObjectCachePool();
        $foreignItem = $this->createMock(\Psr\Cache\CacheItemInterface::class);

        $this->assertFalse($pool->save($foreignItem));
    }

    public function testPoolSaveDeferredRejectsNonWpObjectCacheItem(): void
    {
        $pool = new WpObjectCachePool();
        $foreignItem = $this->createMock(\Psr\Cache\CacheItemInterface::class);

        $this->assertFalse($pool->saveDeferred($foreignItem));
    }

    public function testPoolCacheGroup(): void
    {
        $this->assertSame('tob_auth0', WpObjectCachePool::CONST_CACHE_GROUP);
    }

    protected function tearDown(): void
    {
        wp_cache_flush();
    }
}
