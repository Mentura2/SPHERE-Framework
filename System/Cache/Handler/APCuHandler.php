<?php
namespace SPHERE\System\Cache\Handler;

use SPHERE\System\Cache\CacheFactory;
use SPHERE\System\Cache\CacheStatus;
use SPHERE\System\Config\Reader\ReaderInterface;
use SPHERE\System\Debugger\DebuggerFactory;
use SPHERE\System\Debugger\Logger\BenchmarkLogger;
use SPHERE\System\Debugger\Logger\ErrorLogger;

/**
 * Class APCuHandler
 *
 * @package SPHERE\System\Cache\Handler
 */
class APCuHandler extends AbstractHandler implements HandlerInterface
{

    /**
     * @param ReaderInterface $Name
     * @param ReaderInterface $Config
     *
     * @return HandlerInterface
     */
    public function setConfig($Name, ReaderInterface $Config = null)
    {

        if (function_exists('apc_clear_cache')) {
            return $this;
        }
        (new DebuggerFactory())->createLogger(new ErrorLogger())
            ->addLog(__METHOD__.' Error: APCu not available -> Fallback');
        return (new CacheFactory())->createHandler(new DefaultHandler());
    }

    /**
     * @param string $Key
     * @param mixed  $Value
     * @param int    $Timeout
     * @param string $Region
     *
     * @return APCuHandler
     */
    public function setValue($Key, $Value, $Timeout = 0, $Region = 'Default')
    {

        // MUST NOT USE
        (new DebuggerFactory())->createLogger(new ErrorLogger())
            ->addLog(__METHOD__.' Error: SET - MUST NOT BE USED!');
        return $this;
    }

    /**
     * @param string $Key
     * @param string $Region
     *
     * @return mixed
     */
    public function getValue($Key, $Region = 'Default')
    {

        // MUST NOT USE
        (new DebuggerFactory())->createLogger(new ErrorLogger())
            ->addLog(__METHOD__.' Error: GET - MUST NOT BE USED!');
        return null;
    }

    /**
     * @return APCuHandler
     */
    public function clearCache()
    {

        (new DebuggerFactory())->createLogger(new BenchmarkLogger())->addLog('Clear APCu');
        apc_clear_cache();
        return $this;
    }

    /**
     * @return CacheStatus
     */
    public function getStatus()
    {

        (new DebuggerFactory())->createLogger(new BenchmarkLogger())->addLog('Status APCu');
        $Status = array();
        $Status += apc_sma_info(true);
        $Status += apc_cache_info('user', true);
        return new CacheStatus(
            $Status['nhits'], $Status['nmisses'], $Status['seg_size'],
            $Status['seg_size'] - $Status['avail_mem'], $Status['avail_mem'], 0
        );
    }
}
