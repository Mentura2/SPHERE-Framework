<?php
namespace SPHERE\Application\Education\Graduation\Certificate;

use SPHERE\Application\Education\Graduation\Certificate\Repository\Document;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Element;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Frame;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Page;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Section;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Slice;
use SPHERE\Common\Frontend\IFrontendInterface;
use SPHERE\Common\Frontend\Layout\Structure\Layout;
use SPHERE\Common\Frontend\Layout\Structure\LayoutColumn;
use SPHERE\Common\Frontend\Layout\Structure\LayoutGroup;
use SPHERE\Common\Frontend\Layout\Structure\LayoutRow;
use SPHERE\Common\Window\Stage;
use SPHERE\System\Cache\Handler\TwigHandler;
use SPHERE\System\Extension\Extension;

class HorHJEins extends Extension implements IFrontendInterface
{

    public function frontendCreate($Data, $Content = null)
    {

        // TODO: Find Template in Database (DMS)
        $this->getCache(new TwigHandler())->clearCache();

        $Header = (new Slice())
            ->addSection((new Section())
                ->addElementColumn((new Element())
                    ->setContent('Hormersdorf Halbjahreszeugnis Klasse 1.pdf')
                    ->styleTextSize('12px')
                    ->styleTextColor('#CCC')
                    ->styleAlignCenter()
                    , '25%')
                ->addElementColumn((new Element\Sample())
                    ->styleTextSize('30px')
                )
                ->addElementColumn((new Element())
                    , '25%')
            );

        $Content = (new Frame())->addDocument(
            (new Document())
                ->addPage((new Page())
                    ->addSlice(
                        $Header
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element\Image('/Common/Style/Resource/Logo/Hormersdorf_logo.png', '150px'))
                                ->styleAlignCenter()
                                , '25%')
                            ->addSliceColumn((new Slice())
                                ->addSection((new Section())
                                    ->addElementColumn((new Element())
                                        ->setContent('Name der Schule:')
                                        ->styleTextSize('11px')
                                        ->styleMarginTop('6px')
                                        , '20%')
                                    ->addElementColumn((new Element())
                                        ->setContent('Freie Evangelische Grundschule Hormersdorf')
                                        ->styleTextSize('17px')
                                        ->styleTextBold()
                                        ->styleBorderBottom('1px', '#BBB')
                                        ->styleAlignCenter()
                                        , '80%')
                                )
                                ->addSection((new Section())
                                    ->addElementColumn((new Element())
                                        , '27%')
                                    ->addElementColumn((new Element())
                                        ->setContent('(Staatlich anerkannte Ersatzschule)')
                                        ->styleAlignCenter()
                                        , '73%')
                                )
                                ->styleMarginTop('30px')
                                , '75%')
                        )
                    )
                    ->addSlice((new Slice())
                        ->addElement((new Element())
                            ->setContent('HALBJAHRESINFORMATION')
                            ->styleTextSize('24px')
                            ->styleTextBold()
                            ->styleAlignCenter()
                            ->styleMarginTop('20px')
                        )
                    )
                    ->addSlice((new Slice())
                        ->addElement((new Element())
                            ->setContent('DER GRUNDSCHULE')
                            ->styleTextSize('24px')
                            ->styleTextBold()
                            ->styleAlignCenter()
                        )
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Klasse')
                                ->styleBorderBottom('1px', '#BBB')
                                , '8%')
                            ->addElementColumn((new Element())
                                ->setContent('{{ Data.Division }}')
                                ->styleBorderBottom('1px', '#BBB')
                                , '47%')
                            ->addElementColumn((new Element())
                                ->setContent('1. Schulhalbjahr')
                                ->styleBorderBottom('1px', '#BBB')
                                ->styleAlignRight()
                                , '30%')
                            ->addElementColumn((new Element())
                                ->setContent('{{ Data.School.Year }}')
                                ->styleBorderBottom('1px', '#BBB')
                                ->styleAlignCenter()
                                , '15%')
                        )->styleMarginTop('30px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Vor- und Zuname:')
                                ->styleBorderBottom('1px', '#BBB')
                                , '20%')
                            ->addElementColumn((new Element())
                                ->setContent('{{ Data.Name }}')
                                ->styleBorderBottom('1px', '#BBB')
                                , '80%')
                        )->styleMarginTop('5px')
                    )
                    ->addSlice((new Slice())
                        ->addElement((new Element())
                            ->setContent('Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx ')
                            ->styleMarginTop('15px')
                        )
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Fehltage entschuldigt:')
                                ->styleBorderBottom('1px', '#BBB')
                                , '23%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleBorderBottom('1px', '#BBB')
                                , '10%')
                            ->addElementColumn((new Element())
                                ->setContent('unentschuldigt:')
                                ->styleBorderBottom('1px', '#BBB')
                                , '17%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleBorderBottom('1px', '#BBB')
                                , '50%')
                        )->styleMarginTop('305px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Datum:')
                                ->styleBorderBottom('1px', '#BBB')
                                , '10%')
                            ->addElementColumn((new Element())
                                ->setContent('23.03.2016')
                                ->styleAlignCenter()
                                ->styleBorderBottom('1px', '#BBB')
                                , '25%')
                            ->addElementColumn((new Element())
                                , '65%')
                        )->styleMarginTop('30px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                , '35%')
                            ->addElementColumn((new Element())
                                ->setContent('Dienststempel der Schule')
                                ->styleTextSize('9px')
                                ->styleAlignCenter()
                                , '30%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleBorderBottom('1px', '#BBB')
                                , '35%')
                        )
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                , '65%')
                            ->addElementColumn((new Element())
                                ->setContent('Klassenlehrer/in')
                                ->styleAlignCenter()
                                ->styleTextSize('11px')
                                , '35%')
                        )
                        ->styleMarginTop('30px')
                    )
                    ->addSlice((new Slice())
                        ->addElement((new Element())
                            ->setContent('Zur Kenntnis genommen:')
                            ->styleBorderBottom('1px', '#BBB')
                        )
                        ->styleMarginTop('30px')
                    )
                    ->addSlice((new Slice())
                        ->addElement((new Element())
                            ->setContent('Personensorgeberechtigte/r')
                            ->styleAlignCenter()
                        )
                    )
                )
        );

        $Content->setData($Data);

        $Preview = $Content->getContent();

        $Stage = new Stage();

        $Stage->setContent(new Layout(new LayoutGroup(new LayoutRow(array(
            new LayoutColumn(array(
                '<div class="cleanslate">'.$Preview.'</div>'
            ), 12),
        )))));

        return $Stage;
    }
}