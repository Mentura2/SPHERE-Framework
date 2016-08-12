<?php
namespace SPHERE\System\Database\Filter\Link;

use SPHERE\System\Cache\Handler\DataCacheHandler;
use SPHERE\System\Database\Binding\AbstractService;
use SPHERE\System\Database\Binding\AbstractView;
use SPHERE\System\Database\Filter\Logic\AndLogic;
use SPHERE\System\Database\Filter\Logic\OrLogic;
use SPHERE\System\Database\Fitting\Element;
use SPHERE\System\Extension\Extension;

/**
 * Class AbstractNode
 *
 * @package SPHERE\System\Database\Filter\Pile
 */
abstract class AbstractNode extends Extension
{

    protected static $Cache = false;
    /** @var array $PathList */
    private $PathList = array();
    /** @var Probe[] $ProbeList */
    private $ProbeList = array();
    /** @var int|true $Timeout */
    private $Timeout = 0;

    /**
     *
     * @param AbstractService $Service
     * @param Element         $Entity
     *
     * @return $this
     */
    public function addProbe(AbstractService $Service, Element $Entity)
    {

        array_push($this->ProbeList, new Probe($Service, $Entity));
        return $this;
    }

    /**
     * @param null|string $ParentProperty
     * @param null|string $ChildProperty
     *
     * @return $this
     */
    public function addPath($ParentProperty = null, $ChildProperty = null)
    {

        array_push($this->PathList, array($ParentProperty, $ChildProperty));
        return $this;
    }

    /**
     * @return array
     */
    public function getPathList()
    {

        return $this->PathList;
    }

    /**
     * @param array $Search array( ProbeIndex => array( 'Column' => 'Value', ... ), ... )
     *
     * @param int $Timeout
     * @return bool|\SPHERE\System\Database\Fitting\Element[]
     */
    public function searchData($Search, $Timeout = 60)
    {

        $ProbeList = $this->getProbeList();

        $CacheKey = array();
        $CacheDependency = array();
        foreach ($ProbeList as $Probe) {
            array_push($CacheKey, $Probe->getEntity()->getEntityFullName());
            array_push($CacheDependency, $Probe->getEntity());
        }
        array_push($CacheKey, $Search);
        $Cache = new DataCacheHandler(json_encode($CacheKey), $CacheDependency);

        if (!self::$Cache || null === ( $Result = $Cache->getData() )) {

            $ResultCache = array();

            $Restriction = array();
            foreach ($ProbeList as $Index => $Probe) {
                if (isset( $Search[$Index] )) {
                    $Filter = $Search[$Index];
                } else {
                    $Filter = array();
                }

                $Logic = $this->createLogic($Filter, $Restriction, $Index);

                $EntityList = $Probe->findLogic($Logic);
                // Exit if Path is Empty = NO Result
                if (empty( $EntityList )) {
                    return array();
                }
                $ResultCache[$Index] = $EntityList;

                $PathCurrent = $this->getPath($Index);
                if (isset( $ProbeList[$Index + 1] )) {
                    $PathNext = $this->getPath($Index + 1);

                    $Restriction = array(
                        $PathNext[0] => $Probe->findLogicColumn($Logic, $PathCurrent[1])
                    );
                }
            }

            $Result = $this->parseResult($ResultCache, $Timeout);
            if (!$this->isTimeout() && self::$Cache) {
                $Cache->setData($Result);
            }
        }
        return $Result;
    }

    /**
     * @return Probe[]
     */
    public function getProbeList()
    {

        return $this->ProbeList;
    }

    /**
     * @param array $Search
     * @param array $Restriction
     * @param int   $ProbeIndex
     *
     * @return AndLogic
     */
    public function createLogic($Search, $Restriction, $ProbeIndex)
    {

        $Logic = (new AndLogic($this->getProbe($ProbeIndex)->useBuilder()));
        if (!empty( $Restriction )) {
            $Logic->addLogic(
                (new OrLogic($this->getProbe($ProbeIndex)->useBuilder()))->addCriteriaList(
                    $Restriction, OrLogic::COMPARISON_IN
                )
            );
        }
        if (!empty( $Search )) {
            $Logic->addLogic(
                (new AndLogic($this->getProbe($ProbeIndex)->useBuilder()))->addCriteriaList(
                    $Search, AndLogic::COMPARISON_LIKE
                )
            );
        }
        $Logic->addLogic(
            (new AndLogic($this->getProbe($ProbeIndex)->useBuilder()))->addCriteria(
                'EntityRemove', null, AndLogic::COMPARISON_EXACT
            )
        );
        return $Logic;
    }

    /**
     * @param int $Index
     *
     * @return Probe
     */
    public function getProbe($Index)
    {

        return $this->ProbeList[$Index];
    }

    /**
     * @param int $Index
     *
     * @return array
     */
    public function getPath($Index)
    {

        return $this->PathList[$Index];
    }

    /**
     * @param  $List
     * @param  int $Timeout
     * @return array
     */
    abstract protected function parseResult($List, $Timeout = 60);

    /**
     * @return bool
     */
    public function isTimeout() {
        if( $this->Timeout === true ) {
        return true;
        }
        return false;
    }

    /**
     * @param int $Timeout
     */
    protected function setTimeout($Timeout)
    {

        $this->Timeout = time() + $Timeout;
    }

    /**
     * @return bool
     */
    protected function checkTimeout()
    {
        if( time() > $this->Timeout ) {
            $this->Timeout = true;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @param int   $ParentKey      Id of Parent-Property
     * @param array $List
     * @param int   $ChildListIndex Index of Child-View-List
     *
     * @return array
     */
    protected function filterNodeList($ParentKey, $List, $ChildListIndex)
    {

        return array_filter($List[$ChildListIndex], function (AbstractView $Item) use ($ParentKey, $ChildListIndex) {

            $ChildKey = $Item->__get($this->getPath($ChildListIndex)[0]);
            if ($ParentKey == $ChildKey) {
                return true;
            }
            return false;
        });
    }
}
