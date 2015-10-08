<?php
namespace SPHERE\Application\Education;

use SPHERE\Application\Education\Lesson\Lesson;
use SPHERE\Application\Education\School\School;
use SPHERE\Application\IClusterInterface;
use SPHERE\Common\Main;
use SPHERE\Common\Window\Navigation\Link;
use SPHERE\Common\Window\Stage;

/**
 * Class Education
 *
 * @package SPHERE\Application\Education
 */
class Education implements IClusterInterface
{

    public static function registerCluster()
    {

        School::registerApplication();
        Lesson::registerApplication();

        Main::getDisplay()->addClusterNavigation(
            new Link(new Link\Route(__NAMESPACE__), new Link\Name('Bildung'))
        );
        Main::getDispatcher()->registerRoute(Main::getDispatcher()->createRoute(
            __NAMESPACE__, __CLASS__.'::frontendDashboard'
        ));
    }

    /**
     * @return Stage
     */
    public function frontendDashboard()
    {

        $Stage = new Stage('Dashboard', 'Bildung');

        return $Stage;
    }
}
