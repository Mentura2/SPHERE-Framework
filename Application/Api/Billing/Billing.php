<?php
namespace SPHERE\Application\Api\Billing;

use SPHERE\Application\Api\Billing\Inventory\ApiItem;
use SPHERE\Application\Api\Billing\Inventory\ApiSetting;
use SPHERE\Application\IApplicationInterface;

/**
 * Class Reporting
 *
 * @package SPHERE\Application\Api\Billing
 */
class Billing implements IApplicationInterface
{

    public static function registerApplication()
    {

//        Invoice::registerModule();
        ApiSetting::registerApi();
        ApiItem::registerApi();
    }
}
