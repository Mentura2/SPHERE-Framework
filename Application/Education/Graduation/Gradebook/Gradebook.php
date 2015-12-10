<?php
namespace SPHERE\Application\Education\Graduation\Gradebook;

use SPHERE\Application\IModuleInterface;
use SPHERE\Application\Platform\Gatekeeper\Authorization\Consumer\Consumer;
use SPHERE\Common\Frontend\Icon\Repository\Book;
use SPHERE\Common\Frontend\Icon\Repository\Document;
use SPHERE\Common\Frontend\Icon\Repository\Tag;
use SPHERE\Common\Main;
use SPHERE\Common\Window\Navigation\Link;
use SPHERE\System\Database\Link\Identifier;

/**
 * Class Gradebook
 *
 * @package SPHERE\Application\Education\Graduation\Gradebook
 */
class Gradebook implements IModuleInterface
{

    public static function registerModule()
    {

        Main::getDisplay()->addModuleNavigation(
            new Link(new Link\Route(__NAMESPACE__ . '\GradeType'), new Link\Name('Zensuren-Typ'),
                new Link\Icon(new Tag()))
        );
        Main::getDisplay()->addModuleNavigation(
            new Link(new Link\Route(__NAMESPACE__ . '\Score'), new Link\Name('Berechnungsvorschrift'),
                new Link\Icon(new Book()))
        );
        Main::getDisplay()->addModuleNavigation(
            new Link(new Link\Route(__NAMESPACE__ . '\Test'), new Link\Name('Leistungsermittlung'),
                new Link\Icon(new Document()))
        );
        Main::getDisplay()->addModuleNavigation(
            new Link(new Link\Route(__NAMESPACE__ . '\Headmaster\Test'), new Link\Name('Leistungsermittlung (Leitung)'),
                new Link\Icon(new Document()))
        );
        Main::getDisplay()->addModuleNavigation(
            new Link(new Link\Route(__NAMESPACE__ .'\Gradebook' ), new Link\Name('Notenbuch'),
                new Link\Icon(new Book()))
        );
        Main::getDisplay()->addModuleNavigation(
            new Link(new Link\Route(__NAMESPACE__ .'\Headmaster\Gradebook' ), new Link\Name('Notenbuch (Leitung)'),
                new Link\Icon(new Book()))
        );

        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\GradeType',
                __NAMESPACE__ . '\Frontend::frontendGradeType')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\GradeType\Edit',
                __NAMESPACE__ . '\Frontend::frontendEditGradeType')
        );

        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Gradebook',
                __NAMESPACE__ . '\Frontend::frontendGradebook')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Gradebook\Selected',
                __NAMESPACE__ . '\Frontend::frontendSelectedGradebook')
        );

        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Test',
                __NAMESPACE__ . '\Frontend::frontendTest')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Test\Selected',
                __NAMESPACE__ . '\Frontend::frontendTestSelected')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Test\Edit',
                __NAMESPACE__ . '\Frontend::frontendEditTest')
        );

        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Test\Grade\Edit',
                __NAMESPACE__ . '\Frontend::frontendEditTestGrade')
        );

        /*
         * Headmaster
         */
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Headmaster\Gradebook',
                __NAMESPACE__ . '\Frontend::frontendHeadmasterGradebook')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Headmaster\Gradebook\Selected',
                __NAMESPACE__ . '\Frontend::frontendHeadmasterSelectedGradebook')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Headmaster\Test',
                __NAMESPACE__ . '\Frontend::frontendHeadmasterTest')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Headmaster\Test\Selected',
                __NAMESPACE__ . '\Frontend::frontendHeadmasterTestSelected')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Headmaster\Test\Edit',
                __NAMESPACE__ . '\Frontend::frontendHeadmasterEditTest')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Headmaster\Test\Grade\Edit',
                __NAMESPACE__ . '\Frontend::frontendHeadmasterEditTestGrade')
        );

        /*
         * Score
         */
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Score',
                __NAMESPACE__ . '\Frontend::frontendScore')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Score\Group',
                __NAMESPACE__ . '\Frontend::frontendScoreGroup')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Score\Group\Select',
                __NAMESPACE__ . '\Frontend::frontendScoreGroupSelect')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Score\Group\Add',
                __NAMESPACE__ . '\Frontend::frontendScoreGroupAdd')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Score\Group\Remove',
                __NAMESPACE__ . '\Frontend::frontendScoreGroupRemove')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Score\Group\GradeType\Select',
                __NAMESPACE__ . '\Frontend::frontendScoreGroupGradeTypeSelect')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Score\Group\GradeType\Add',
                __NAMESPACE__ . '\Frontend::frontendScoreGroupGradeTypeAdd')
        );
        Main::getDispatcher()->registerRoute(
            Main::getDispatcher()->createRoute(__NAMESPACE__ . '\Score\Group\GradeType\Remove',
                __NAMESPACE__ . '\Frontend::frontendScoreGroupGradeTypeRemove')
        );
    }

    /**
     * @return Service
     */
    public static function useService()
    {
        return new Service(new Identifier('Education', 'Graduation', 'Gradebook', null,
            Consumer::useService()->getConsumerBySession()),
            __DIR__ . '/Service/Entity', __NAMESPACE__ . '\Service\Entity'
        );
    }

    /**
     * @return Frontend
     */
    public static function useFrontend()
    {
        return new Frontend();
    }
}
