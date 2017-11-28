<?php

namespace SPHERE\Application\Api\Education\Certificate\Generator\Repository\CMS;

use SPHERE\Application\Education\Certificate\Generator\Repository\Element;
use SPHERE\Application\Education\Certificate\Generator\Repository\Page;
use SPHERE\Application\Education\Certificate\Generator\Repository\Section;
use SPHERE\Application\Education\Certificate\Generator\Repository\Slice;
use SPHERE\Application\People\Person\Service\Entity\TblPerson;

/**
 * Class CmsGsJ
 * @package SPHERE\Application\Api\Education\Certificate\Generator\Repository\CMS
 */
class CmsGsJ extends CmsStyle
{


    /**
     * @param TblPerson|null $tblPerson
     *
     * @return Page
     * @internal param bool $IsSample
     *
     */
    public function buildPages(TblPerson $tblPerson = null)
    {

        $personId = $tblPerson ? $tblPerson->getId() : 0;

        return (new Page())
            ->addSlice((new Slice())
                ->stylePaddingTop('20px')
                ->stylePaddingLeft('16px')
                ->stylePaddingRight('16px')
                ->addSection((new Section())
                    ->addSliceColumn(
                        self::getCMSHead()
                    )
                )
                ->addElement((new Element())
                    ->styleMarginTop('10px')
                )
                ->addSectionList(
                    self::getCMSSchoolLine('Staatlich anerkannte Ersatzschule in Trägerschaft von Christen machen Schule
                    Zwickau gemeinnützige GmbH', 'Evangelische Schule "Stephan Roth" (Grundschule)')
                )
                ->addElement((new Element())
                    ->styleMarginTop('10px')
                )
                ->addSection(
                    self::getCMSHeadLine('Jahreseinschätzung')
                )
                ->addElement((new Element())
                    ->styleMarginTop('20px')
                )
                ->addSection(
                    self::getCMSDivisionAndYear($personId)
                )
                ->addElement((new Element())
                    ->styleMarginTop('20px')
                )
                ->addSection(
                    self::getCMSName($personId)
                )
                ->addElement((new Element())
                    ->styleMarginTop('10px')
                )
                ->addSection((new Section())
                    ->addSliceColumn(
                        self::getCMSHeadGrade($personId)
                    )
                )
                ->addElement((new Element())
                    ->styleMarginTop('25px')
                )
                ->addSection((new Section())
                    ->addSliceColumn(
                        self::getCMSSubjectLanes($personId, false, '60px')
                    )
                )
                ->addElement((new Element())
                    ->styleMarginTop('20px')
                )
                ->addSectionList(
                    self::getCMSRemark($personId, '340px')
                )
                ->addSection(
                    self::getCMSMissing($personId)
                )
                ->addElement((new Element())
                    ->styleMarginTop('15px')
                )
                ->addSection(
                    self::getCMSDate($personId)
                )
                ->addElement((new Element())
                    ->styleMarginTop('10px')
                )
                ->addSection((new Section())
                    ->addSliceColumn(
                        self::getCMSTeacher($personId, true)
                    )
                )
                ->addElement((new Element())
                    ->styleMarginTop('20px')
                )
                ->addSectionList(
                    self::getCMSCustody()
                )
                ->addSectionList(
                    self::getCMSFoot()
                )
            );
    }
}